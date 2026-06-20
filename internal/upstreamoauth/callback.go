package upstreamoauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
)

// CallbackHandler handles GET /upstream/callback/{routeName}.
// It validates the state parameter, exchanges the authorization code for an
// upstream access token, and stores the result in UpstreamTokenStore.
// Subject recovery uses the state store — not middleware.IdentityFromContext —
// because the callback may arrive outside the gateway auth middleware chain.
type CallbackHandler struct {
	stateStore StateStore
	manager    *Manager
	tokenStore auth.UpstreamTokenStore
	publicURL  string
	httpClient *http.Client
}

// NewCallbackHandler creates a CallbackHandler. If httpClient is nil,
// a client with DefaultHTTPTimeout is used.
func NewCallbackHandler(
	stateStore StateStore,
	manager *Manager,
	tokenStore auth.UpstreamTokenStore,
	publicURL string,
	httpClient *http.Client,
) *CallbackHandler {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &CallbackHandler{
		stateStore: stateStore,
		manager:    manager,
		tokenStore: tokenStore,
		publicURL:  strings.TrimRight(publicURL, "/"),
		httpClient: httpClient,
	}
}

func (h *CallbackHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	routeName := r.PathValue("routeName")
	if routeName == "" {
		http.Error(w, "missing route name", http.StatusBadRequest)
		return
	}

	stateKey := r.URL.Query().Get("state")
	if stateKey == "" {
		http.Error(w, "missing state parameter", http.StatusBadRequest)
		return
	}

	// Pop the state immediately once stateKey is present, even when code is
	// absent or the upstream returned an error. Consuming the state before any
	// early return prevents state reuse if the state value is leaked.
	state, ok := h.stateStore.Pop(stateKey)
	if !ok {
		slog.Warn("upstream OAuth callback: invalid or expired state",
			"route", routeName,
			"state_prefix", stateKey[:min(8, len(stateKey))],
		)
		http.Error(w, "invalid or expired state", http.StatusBadRequest)
		return
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		errParam := r.URL.Query().Get("error")
		if errParam == "" {
			errParam = "unknown_error"
		}
		http.Error(w, "authorization denied: "+errParam, http.StatusBadRequest)
		return
	}

	if state.RouteName != routeName {
		slog.Warn("upstream OAuth callback: route name mismatch",
			"expected", state.RouteName, "got", routeName)
		http.Error(w, "state route mismatch", http.StatusBadRequest)
		return
	}

	rec, ok := h.manager.LoadClient(routeName)
	if !ok || rec.ClientID == "" {
		slog.Error("upstream OAuth callback: no client registration for route", "route", routeName)
		http.Error(w, "upstream client not registered", http.StatusInternalServerError)
		return
	}

	redirectURI := fmt.Sprintf("%s/upstream/callback/%s",
		h.publicURL,
		url.PathEscape(routeName),
	)

	tokenResp, err := h.exchangeCode(r.Context(), rec, code, state.CodeVerifier, redirectURI)
	if err != nil {
		slog.Error("upstream OAuth callback: token exchange failed", "route", routeName, "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	// Reject tokens with no expiry information: storing a zero ExpiresAt would
	// cause Lookup to treat the token as permanently valid, which is unsafe for
	// upstream access tokens that may be silently revoked by the upstream AS.
	if tokenResp.ExpiresIn <= 0 {
		slog.Error("upstream OAuth callback: token response missing required expires_in",
			"route", routeName, "token_endpoint", rec.TokenEndpoint)
		http.Error(w, "upstream token missing required expiry", http.StatusBadGateway)
		return
	}
	expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	if err := h.tokenStore.Save(state.Subject, routeName, auth.UpstreamTokenRecord{
		Grant:        "authorization_code",
		Issuer:       rec.Issuer,
		AccessToken:  tokenResp.AccessToken,
		RefreshToken: tokenResp.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        tokenResp.Scope,
	}); err != nil {
		slog.Error("upstream OAuth callback: failed to save token", "route", routeName, "err", err)
		http.Error(w, "failed to save token", http.StatusInternalServerError)
		return
	}

	slog.Info("upstream OAuth: authorization complete",
		"route", routeName,
		"subject_hash", subjectHash(state.Subject),
	)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w,
		"<html><body><p>Authorization complete. You may now access <strong>%s</strong>.</p></body></html>",
		routeName,
	)
}

// tokenExchangeResponse is the subset of the OAuth 2.0 token response used here.
type tokenExchangeResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int64  `json:"expires_in,omitempty"`
	Scope        string `json:"scope,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
}

func (h *CallbackHandler) exchangeCode(
	ctx context.Context,
	rec ClientRecord,
	code, codeVerifier, redirectURI string,
) (*tokenExchangeResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("code_verifier", codeVerifier)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", rec.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rec.TokenEndpoint,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if rec.ClientSecret != "" {
		req.SetBasicAuth(rec.ClientID, rec.ClientSecret)
	}

	resp, err := h.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", rec.TokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, fmt.Errorf("token endpoint %s: unexpected status %d: %s",
			rec.TokenEndpoint, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var tr tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decoding token response from %s: %w", rec.TokenEndpoint, err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response from %s missing access_token", rec.TokenEndpoint)
	}
	return &tr, nil
}

// subjectHash returns a short hex prefix of the subject SHA256 for safe logging.
func subjectHash(subject string) string {
	h := sha256.Sum256([]byte(subject))
	return fmt.Sprintf("%x", h[:4])
}
