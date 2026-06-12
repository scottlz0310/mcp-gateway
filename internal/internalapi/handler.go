// Package internalapi は delegated access (#72) と認証失敗診断 (#102) の
// internal endpoint を提供する。loopback listener と shared secret の両方を
// 必須とし、trusted upstream だけに access token 取得と監査診断を許可する。
// non-loopback bind は cmd/server の起動時に拒否する。
package internalapi

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
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

// FailureReader は機密情報除外済みの直近 OAuth 失敗 snapshot を提供する。
// 実 auth handler は authaudit.FileRecorder へ処理を委譲する。
type FailureReader interface {
	RecentAuthFailures() []authaudit.Event
}

// Handler serves the loopback-only internal API.
type Handler struct {
	resolver TokenResolver
	failures FailureReader
	secret   string
}

type HandlerOption func(*Handler)

// WithFailureReader は OAuth 失敗診断 endpoint を有効化する。
func WithFailureReader(reader FailureReader) HandlerOption {
	return func(h *Handler) {
		h.failures = reader
	}
}

// NewHandler builds the internal API handler. The secret must be at least
// MinSecretLength characters; shorter secrets are an error so the caller
// (cmd/server) can fail closed at startup rather than serving a weak
// boundary.
func NewHandler(resolver TokenResolver, secret string, opts ...HandlerOption) (*Handler, error) {
	if resolver == nil {
		return nil, errors.New("internalapi: resolver must not be nil")
	}
	if len(secret) < MinSecretLength {
		return nil, errors.New("internalapi: shared secret must be at least 32 characters")
	}
	handler := &Handler{resolver: resolver, secret: secret}
	for _, opt := range opts {
		opt(handler)
	}
	return handler, nil
}

// RegisterRoutes は delegated access と認証診断 route を mux へ登録する。
//
// We register the route without an HTTP method prefix and check r.Method
// inside the handler. The Go 1.22+ ServeMux method-matching syntax
// ("POST /path") would auto-respond to other methods with a plain-text
// 405, bypassing our JSON error envelope.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/internal/v1/whoami", h.Whoami)
	mux.HandleFunc("/internal/v1/auth/failures", h.AuthFailures)
}

type authFailuresResponse struct {
	Failures []authaudit.Event `json:"failures"`
}

// AuthFailures は直近の OAuth 失敗を最新順で返す。
// delegated access と同じ loopback + pre-shared-secret 境界を使用する。
func (h *Handler) AuthFailures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
	if !isLoopback(r.RemoteAddr) {
		writeError(w, http.StatusForbidden, "loopback_required")
		return
	}
	if !h.checkAuth(r) {
		writeError(w, http.StatusUnauthorized, "invalid_authorization")
		return
	}
	if h.failures == nil {
		writeError(w, http.StatusServiceUnavailable, "diagnostics_unavailable")
		return
	}

	limit := authaudit.DefaultFailureLimit
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		parsed, err := strconv.Atoi(raw)
		if err != nil || parsed <= 0 || parsed > authaudit.DefaultFailureLimit {
			writeError(w, http.StatusBadRequest, "invalid_limit")
			return
		}
		limit = parsed
	}
	failures := h.failures.RecentAuthFailures()
	if len(failures) > limit {
		failures = failures[:limit]
	}
	if failures == nil {
		failures = []authaudit.Event{}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if err := json.NewEncoder(w).Encode(authFailuresResponse{Failures: failures}); err != nil {
		slog.Warn("internalapi: auth failures response encode failed", "err", err)
	}
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
// HTTP status codes. The status surface is:
//
//   - 200: usable token returned (cached or freshly rotated).
//   - 400: malformed request body, oversized body, missing subject, or
//     trailing data after the JSON object.
//   - 401: missing or invalid shared secret.
//   - 403: request did not arrive over a loopback address.
//   - 404: no cached token entry exists for the subject. NOTE: this is
//     not a strong enumeration-resistance guarantee -- a caller already
//     holding the shared secret could learn the same fact via the OAuth
//     flow. Stricter enumeration resistance is future work.
//   - 405: non-POST method.
//   - 502: rotation_failed (token is in the leeway window and rotation
//     did not yield a fresh token) or upstream_failure (other resolver
//     errors).
func (h *Handler) Whoami(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed")
		return
	}
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
	// Reject any trailing tokens after the JSON object so callers can't
	// sneak in extra payload past DisallowUnknownFields. dec.More() alone
	// is insufficient: it returns false for a stray closing delimiter
	// (`]`, `}`) or whitespace-only suffix because those tokens do not
	// begin a new JSON value. A second Decode that must return io.EOF
	// definitively confirms the stream contained exactly one JSON value.
	var trailing json.RawMessage
	if err := dec.Decode(&trailing); !errors.Is(err, io.EOF) {
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
		if errors.Is(err, auth.ErrRotationFailed) {
			slog.Warn("internalapi: whoami rotation failed",
				"subject", subject,
				"err", err,
			)
			writeError(w, http.StatusBadGateway, "rotation_failed")
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
		// Map to the same upstream_failure code used for rotation
		// failures: from the caller's perspective both indicate "the
		// gateway could not produce a usable bearer", which is the
		// documented public contract. Keeping a distinct internal code
		// would force callers to handle two equivalent failure modes.
		slog.Warn("internalapi: whoami returned empty access token despite no error",
			"subject", subject,
		)
		writeError(w, http.StatusBadGateway, "upstream_failure")
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
	w.Header().Set("Pragma", "no-cache")
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
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code})
}
