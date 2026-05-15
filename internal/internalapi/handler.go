// Package internalapi implements the Phase B delegated-access PoC endpoints
// (#72). The handlers in this package serve a loopback-only HTTP listener
// and let trusted upstream MCP processes fetch the latest valid access
// token for a known subject without re-doing the OAuth user flow.
//
// Trust boundary: the listener MUST bind to a loopback address (127.0.0.1
// or ::1) and requests MUST present the configured shared secret in the
// Authorization header. Both controls are enforced; binding to a non-loopback
// address is a startup error in cmd/server.
package internalapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
)

// MinSecretLength is the smallest acceptable shared secret length.
// 32 chars (~192 bits at base64-ish entropy) balances usability with
// resistance to online guessing across a loopback boundary.
const MinSecretLength = 32

// MaxRequestBodyBytes caps the request body to defend against memory
// exhaustion on this otherwise tiny endpoint.
const MaxRequestBodyBytes = 4 * 1024

// TokenResolver is the subset of *auth.Handler used by the internal API.
// Defined as an interface so tests can substitute a fake without spinning up
// the full OAuth handler stack.
type TokenResolver interface {
	EnsureFreshAccessTokenForSubject(ctx context.Context, subject string) (auth.DelegatedAccessResult, error)
}

// Handler serves the loopback-only internal API.
type Handler struct {
	resolver TokenResolver
	secret   string
}

// NewHandler builds the internal API handler. The secret must be at least
// MinSecretLength characters; shorter secrets are an error so the caller
// (cmd/server) can fail closed at startup rather than serving a weak
// boundary.
func NewHandler(resolver TokenResolver, secret string) (*Handler, error) {
	if resolver == nil {
		return nil, errors.New("internalapi: resolver must not be nil")
	}
	if len(secret) < MinSecretLength {
		return nil, errors.New("internalapi: shared secret must be at least 32 characters")
	}
	return &Handler{resolver: resolver, secret: secret}, nil
}

// RegisterRoutes wires the internal API onto mux. Currently a single
// endpoint, but kept as a method so future delegated-access routes can be
// added without touching the listener wiring.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /internal/v1/whoami", h.Whoami)
}

// whoamiRequest is the body shape for POST /internal/v1/whoami.
type whoamiRequest struct {
	Subject string `json:"subject"`
}

// whoamiResponse mirrors a normalized OAuth token response, omitting the
// refresh token by design: callers MUST NOT persist it.
type whoamiResponse struct {
	AccessToken string   `json:"access_token"`
	TokenType   string   `json:"token_type"`
	ExpiresAt   string   `json:"expires_at,omitempty"`
	Scopes      []string `json:"scopes,omitempty"`
}

// Whoami returns the latest valid access token for the requested subject,
// rotating it transparently when its provider expiry is within the
// configured leeway.
//
// Errors are returned as JSON {"error": "<code>"} bodies with appropriate
// HTTP status codes. We deliberately do NOT distinguish "subject not found"
// from "subject found but no rotation metadata" so that an attacker holding
// the shared secret cannot use the endpoint as a subject-enumeration oracle
// beyond what they could already discover from the OAuth flow.
func (h *Handler) Whoami(w http.ResponseWriter, r *http.Request) {
	if !isLoopback(r.RemoteAddr) {
		// Defense-in-depth: the listener should only bind to loopback,
		// but if it ever drifts (misconfigured reverse proxy, future
		// refactor) we refuse the request here too.
		writeError(w, http.StatusForbidden, "loopback_required")
		return
	}
	if !h.checkAuth(r) {
		writeError(w, http.StatusUnauthorized, "invalid_authorization")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, MaxRequestBodyBytes)
	var req whoamiRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_body")
		return
	}
	subject := strings.TrimSpace(req.Subject)
	if subject == "" {
		writeError(w, http.StatusBadRequest, "missing_subject")
		return
	}

	result, err := h.resolver.EnsureFreshAccessTokenForSubject(r.Context(), subject)
	if err != nil {
		if errors.Is(err, auth.ErrSubjectNotFound) {
			writeError(w, http.StatusNotFound, "subject_not_found")
			return
		}
		slog.Warn("internalapi: whoami lookup failed",
			"subject", subject,
			"err", err,
		)
		writeError(w, http.StatusBadGateway, "upstream_failure")
		return
	}
	if result.AccessToken == "" {
		// Defensive: should not happen given the contract above, but
		// returning an empty access_token would silently break callers.
		writeError(w, http.StatusBadGateway, "empty_access_token")
		return
	}
	resp := whoamiResponse{
		AccessToken: result.AccessToken,
		TokenType:   "bearer",
		Scopes:      result.Scopes,
	}
	if !result.ProviderAccessExpiry.IsZero() {
		resp.ExpiresAt = result.ProviderAccessExpiry.UTC().Format(time.RFC3339)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		// At this point the status line has already been sent (the
		// json encoder writes 200 implicitly on its first write), so
		// the best we can do is log.
		slog.Warn("internalapi: whoami response encode failed", "err", err)
	}
}

// checkAuth performs a constant-time comparison of the Bearer token in the
// Authorization header against the configured shared secret.
func (h *Handler) checkAuth(r *http.Request) bool {
	authz := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authz) <= len(prefix) || !strings.EqualFold(authz[:len(prefix)], prefix) {
		return false
	}
	presented := authz[len(prefix):]
	if len(presented) != len(h.secret) {
		// ConstantTimeCompare requires equal-length inputs to be
		// meaningful; a length mismatch is itself a non-match.
		return false
	}
	return subtle.ConstantTimeCompare([]byte(presented), []byte(h.secret)) == 1
}

// isLoopback reports whether the given remote address is a loopback IP.
// Accepts both bare IPs (test servers) and host:port forms (real net/http).
func isLoopback(remoteAddr string) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(strings.TrimSpace(host))
	if ip == nil {
		return false
	}
	return ip.IsLoopback()
}

// writeError writes a small JSON error envelope and HTTP status.
// Kept package-private so the error vocabulary stays consistent across
// future endpoints in this package.
func writeError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
