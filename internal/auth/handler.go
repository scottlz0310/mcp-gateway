package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"log/slog"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

// githubClient is the HTTP client used for GitHub Device Flow API calls.
// Exposed as a package-level var so tests can substitute a test server transport.
var githubClient = &http.Client{Timeout: 15 * time.Second}

// Config holds OAuth façade configuration. Provider-specific fields (client
// credentials, scope) live on the Provider implementation; this struct only
// carries gateway-wide settings.
type Config struct {
	BaseURL              string
	SessionTTL           time.Duration
	CacheTTL             time.Duration
	AllowedRedirectHosts []string
	// ExpiresIn controls the expires_in field in token responses (RFC 6749 §5.1).
	// GitHub classic OAuth tokens do not expire on GitHub's side; this only
	// controls how long the MCP client trusts its cached copy. Defaults to 90 days.
	ExpiresIn time.Duration
	// TokenStorePath is the path to the JSON file used for persistent token storage.
	// When empty, an in-memory store is used (default; data lost on restart).
	// When set, validated tokens survive container restarts; the file is written
	// with mode 0600 and only hashed token keys are stored.
	TokenStorePath string
}

// Handler implements the OAuth façade endpoints, delegating provider-specific
// operations to a provider.Provider.
type Handler struct {
	cfg      Config
	provider provider.Provider
	store    *Store
}

// NewHandler creates a new OAuth Handler with the given configuration and provider.
// It returns an error if the provider is nil or if the persistent token store
// cannot be initialized.
//
// When cfg.TokenStorePath is non-empty, validated tokens are stored durably in a
// JSON file so that MCP clients do not need to re-authenticate after gateway
// restarts. Tokens are stored with TTL equal to cfg.ExpiresIn (default 90 days).
// When cfg.TokenStorePath is empty, an in-memory store is used (TTL = cfg.CacheTTL).
func NewHandler(cfg Config, p provider.Provider) (*Handler, error) {
	if p == nil {
		return nil, fmt.Errorf("auth.NewHandler: provider must not be nil")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if len(cfg.AllowedRedirectHosts) == 0 {
		cfg.AllowedRedirectHosts = []string{"localhost", "127.0.0.1", "vscode.dev"}
	}
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = 90 * 24 * time.Hour
	}

	var ts TokenStore
	var tokensTTL time.Duration
	if cfg.TokenStorePath != "" {
		fileStore, err := NewFileTokenStore(cfg.TokenStorePath)
		if err != nil {
			return nil, fmt.Errorf("auth.NewHandler: token store: %w", err)
		}
		ts = fileStore
		tokensTTL = cfg.ExpiresIn
	} else {
		ts = NewMemTokenStore()
		tokensTTL = cfg.CacheTTL
	}

	return &Handler{
		cfg:      cfg,
		provider: p,
		store:    NewStore(cfg.SessionTTL, tokensTTL, ts),
	}, nil
}

// Discovery returns RFC 8414 authorization server metadata.
func (h *Handler) Discovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                           h.cfg.BaseURL,
		"authorization_endpoint":           h.cfg.BaseURL + "/authorize",
		"token_endpoint":                   h.cfg.BaseURL + "/token",
		"registration_endpoint":            h.cfg.BaseURL + "/register",
		"device_authorization_endpoint":    h.cfg.BaseURL + "/device_authorization",
		"response_types_supported":         []string{"code"},
		"grant_types_supported":            []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
		"code_challenge_methods_supported": []string{"S256"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// Register implements RFC 7591 Dynamic Client Registration (pseudo).
// Always returns the configured upstream OAuth App client_id.
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)

	meta := map[string]json.RawMessage{}
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&meta); err != nil {
		jsonError(w, "invalid_client_metadata", "request body must be valid JSON client metadata", http.StatusBadRequest)
		return
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		jsonError(w, "invalid_client_metadata", "request body must contain a single JSON object", http.StatusBadRequest)
		return
	}

	resp := map[string]any{
		"client_id":                  h.provider.ClientID(),
		"client_id_issued_at":        time.Now().Unix(),
		"client_secret_expires_at":   0,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code"},
		"response_types":             []string{"code"},
	}
	for _, field := range []string{"redirect_uris", "client_name", "scope"} {
		if v, ok := meta[field]; ok {
			resp[field] = v
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(resp)
}

// Authorize redirects the MCP client to the configured OAuth provider.
func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	state := q.Get("state")
	redirectURI := q.Get("redirect_uri")
	codeChallenge := q.Get("code_challenge")
	responseType := q.Get("response_type")
	codeChallengeMethod := q.Get("code_challenge_method")

	if responseType != "code" {
		oauthError(w, "unsupported_response_type", "response_type must be 'code'", http.StatusBadRequest)
		return
	}
	if state == "" || redirectURI == "" {
		oauthError(w, "invalid_request", "missing state or redirect_uri", http.StatusBadRequest)
		return
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		oauthError(w, "invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil ||
		(parsedRedirect.Scheme != "http" && parsedRedirect.Scheme != "https") ||
		parsedRedirect.Host == "" ||
		parsedRedirect.Fragment != "" {
		oauthError(w, "invalid_request", "invalid redirect_uri: must be absolute http/https URL without fragment", http.StatusBadRequest)
		return
	}
	if !isAllowedRedirectHost(parsedRedirect.Hostname(), h.cfg.AllowedRedirectHosts) {
		oauthError(w, "invalid_request", "redirect_uri host not permitted", http.StatusBadRequest)
		return
	}

	h.store.SaveSession(state, redirectURI, codeChallenge)

	http.Redirect(w, r, h.provider.AuthorizeURL(state, codeChallenge), http.StatusFound)
}

// Callback receives the provider's authorization code and exchanges it for
// an access token via the Provider implementation.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")

	if code == "" || state == "" {
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	if !h.store.HasSession(state) {
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	accessToken, scopes, err := h.provider.ExchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("OAuth token exchange failed", "provider", h.provider.Name(), "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	internalCode, err := h.store.CompleteCallback(state, accessToken, joinScopes(scopes))
	if err != nil {
		slog.Error("session completion failed", "err", err)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	sess := h.store.lookupByCode(internalCode)
	if sess == nil {
		http.Error(w, "session lost", http.StatusInternalServerError)
		return
	}

	redirect, _ := url.Parse(sess.RedirectURI)
	rq := redirect.Query()
	rq.Set("code", internalCode)
	rq.Set("state", state)
	redirect.RawQuery = rq.Encode()

	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// Token dispatches to the appropriate grant handler based on grant_type.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "malformed request body", http.StatusBadRequest)
		return
	}
	switch r.FormValue("grant_type") {
	case "authorization_code":
		h.tokenAuthCode(w, r)
	case "urn:ietf:params:oauth:grant-type:device_code":
		h.tokenDeviceGrant(w, r)
	case "refresh_token":
		h.tokenRefresh(w, r)
	default:
		oauthError(w, "unsupported_grant_type", "unsupported grant_type", http.StatusBadRequest)
	}
}

func (h *Handler) tokenAuthCode(w http.ResponseWriter, r *http.Request) {
	token, grantedScope, err := h.store.ExchangeCode(
		r.FormValue("code"),
		r.FormValue("redirect_uri"),
		r.FormValue("code_verifier"),
	)
	if err != nil {
		slog.Warn("token exchange rejected", "err", err)
		oauthError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}
	refreshToken, rtErr := h.store.CreateRefreshToken(token, h.cfg.ExpiresIn+30*24*time.Hour)
	if rtErr != nil {
		slog.Warn("failed to create refresh token", "err", rtErr)
	}
	h.writeTokenResponse(w, token, grantedScope, refreshToken)
}

func (h *Handler) tokenDeviceGrant(w http.ResponseWriter, r *http.Request) {
	deviceCode := r.FormValue("device_code")
	if deviceCode == "" {
		oauthError(w, "invalid_request", "missing device_code", http.StatusBadRequest)
		return
	}

	pending, ok := h.store.GetDevice(deviceCode)
	if !ok {
		oauthError(w, "invalid_grant", "device code not found", http.StatusBadRequest)
		return
	}
	if time.Now().After(pending.ExpiresAt) {
		oauthError(w, "expired_token", "device code expired", http.StatusBadRequest)
		return
	}

	switch pending.Status {
	case deviceDenied:
		oauthError(w, "access_denied", "user denied authorization", http.StatusBadRequest)
		return
	}

	// Status is pending: poll GitHub on behalf of the client.
	result, err := h.pollGitHubDeviceToken(r.Context(), pending.GitHubDevCode)
	if err != nil {
		slog.Error("GitHub device token poll failed", "err", err)
		oauthError(w, "server_error", "upstream error polling GitHub", http.StatusBadGateway)
		return
	}

	switch result.Error {
	case "":
		if _, ok := h.store.AuthorizeAndConsumeDevice(deviceCode, result.AccessToken, result.Scope); !ok {
			oauthError(w, "invalid_grant", "device code already consumed", http.StatusBadRequest)
			return
		}
		refreshToken, rtErr := h.store.CreateRefreshToken(result.AccessToken, h.cfg.ExpiresIn+30*24*time.Hour)
		if rtErr != nil {
			slog.Warn("failed to create refresh token", "err", rtErr)
		}
		h.writeTokenResponse(w, result.AccessToken, result.Scope, refreshToken)
	case "authorization_pending":
		oauthError(w, "authorization_pending", "user has not yet authorized the device", http.StatusBadRequest)
	case "slow_down":
		// RFC 8628 §3.5: client must increase polling interval by 5 seconds
		oauthError(w, "slow_down", "polling too frequently, increase interval by 5 seconds", http.StatusBadRequest)
	case "expired_token":
		oauthError(w, "expired_token", "device code expired on GitHub", http.StatusBadRequest)
	case "access_denied":
		h.store.DenyDevice(deviceCode)
		oauthError(w, "access_denied", "user denied authorization", http.StatusBadRequest)
	default:
		slog.Warn("unexpected GitHub device poll error", "error", result.Error)
		oauthError(w, "server_error", "unexpected upstream error: "+result.Error, http.StatusBadGateway)
	}
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token, scope, refreshToken string) {
	expiresIn := max(int64(h.cfg.ExpiresIn/time.Second), 1)
	resp := map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   expiresIn,
	}
	if scope != "" {
		resp["scope"] = scope
	}
	if refreshToken != "" {
		resp["refresh_token"] = refreshToken
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	_ = json.NewEncoder(w).Encode(resp)
}

// tokenRefresh handles grant_type=refresh_token (RFC 6749 §6).
// It validates the presented refresh token, re-checks the underlying access
// token against the provider, rotates the refresh token, and returns a fresh
// token response.  Rotation prevents replay attacks: each refresh token is
// single-use and replaced atomically.
func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		oauthError(w, "invalid_request", "missing refresh_token", http.StatusBadRequest)
		return
	}

	accessToken, err := h.store.UseRefreshToken(rt)
	if err != nil {
		slog.Warn("refresh token rejected", "err", err)
		oauthError(w, "invalid_grant", "refresh token not found or expired", http.StatusBadRequest)
		return
	}

	// Re-validate the underlying token; this uses the cache to avoid an
	// upstream round-trip on every refresh when the token is still warm.
	if _, valErr := h.ValidateToken(r.Context(), accessToken); valErr != nil {
		slog.Warn("refresh rejected: underlying token invalid", "err", valErr)
		oauthError(w, "invalid_grant", "underlying token no longer valid", http.StatusBadRequest)
		return
	}

	// Rotate: issue a new refresh token before returning the access token.
	newRT, rtErr := h.store.CreateRefreshToken(accessToken, h.cfg.ExpiresIn+30*24*time.Hour)
	if rtErr != nil {
		slog.Error("failed to rotate refresh token", "err", rtErr)
		oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
		return
	}

	h.writeTokenResponse(w, accessToken, "", newRT)
}

// DeviceAuthorize handles POST /device_authorization (RFC 8628).
// It requests a device code from GitHub and returns the user_code and verification_uri to the client.
// client_secret is NOT required for GitHub's Device Flow.
func (h *Handler) DeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		oauthError(w, "invalid_request", "malformed request body", http.StatusBadRequest)
		return
	}

	// Always use configured scopes to prevent clients from escalating to broader permissions.
	scope := h.provider.Scopes()

	ghResp, err := h.startGitHubDeviceFlow(r.Context(), scope)
	if err != nil {
		slog.Error("GitHub device flow start failed", "err", err)
		oauthError(w, "server_error", "failed to start device flow with GitHub", http.StatusBadGateway)
		return
	}

	expiresAt := time.Now().Add(time.Duration(ghResp.ExpiresIn) * time.Second)
	internalCode, err := h.store.CreateDevice(ghResp.DeviceCode, ghResp.UserCode, ghResp.VerificationURI, expiresAt, ghResp.Interval)
	if err != nil {
		slog.Error("device session creation failed", "err", err)
		oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
		return
	}

	resp := map[string]any{
		"device_code":      internalCode, // gateway-internal; client uses this to poll /token
		"user_code":        ghResp.UserCode,
		"verification_uri": ghResp.VerificationURI,
		"expires_in":       ghResp.ExpiresIn,
		"interval":         ghResp.Interval,
	}
	if ghResp.VerificationURIComplete != "" {
		resp["verification_uri_complete"] = ghResp.VerificationURIComplete
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(resp)
}

type githubDeviceCodeResp struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

type githubDevicePollResult struct {
	AccessToken string
	Scope       string
	Error       string // GitHub error code; empty on success
}

func (h *Handler) startGitHubDeviceFlow(ctx context.Context, scope string) (*githubDeviceCodeResp, error) {
	form := url.Values{
		"client_id": {h.provider.ClientID()},
		"scope":     {scope},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/device/code",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating GitHub device code request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := githubClient.Do(req)
	if err != nil {
		return nil, &provider.UpstreamError{Err: fmt.Errorf("GitHub device code endpoint: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, &provider.UpstreamError{Err: fmt.Errorf("GitHub device code returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))}
	}

	var result githubDeviceCodeResp
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding GitHub device code response: %w", err)
	}
	if result.DeviceCode == "" || result.UserCode == "" {
		return nil, fmt.Errorf("incomplete device code response from GitHub")
	}
	if result.Interval == 0 {
		result.Interval = 5 // RFC 8628 default
	}
	return &result, nil
}

func (h *Handler) pollGitHubDeviceToken(ctx context.Context, githubDevCode string) (*githubDevicePollResult, error) {
	form := url.Values{
		"client_id":   {h.provider.ClientID()},
		"device_code": {githubDevCode},
		"grant_type":  {"urn:ietf:params:oauth:grant-type:device_code"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://github.com/login/oauth/access_token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating GitHub device token request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := githubClient.Do(req)
	if err != nil {
		return nil, &provider.UpstreamError{Err: fmt.Errorf("GitHub device token endpoint: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		return nil, &provider.UpstreamError{Err: fmt.Errorf("GitHub device token returned %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))}
	}

	var raw struct {
		AccessToken string `json:"access_token"`
		Scope       string `json:"scope"`
		TokenType   string `json:"token_type"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding GitHub device token response: %w", err)
	}
	if raw.Error == "" && raw.AccessToken == "" {
		return nil, fmt.Errorf("GitHub device token response: no access_token and no error field")
	}
	return &githubDevicePollResult{
		AccessToken: raw.AccessToken,
		Scope:       raw.Scope,
		Error:       raw.Error,
	}, nil
}

// ValidateToken checks the bearer token via the provider (with cache).
// The returned subject is the Identity.Subject from the provider.
func (h *Handler) ValidateToken(ctx context.Context, token string) (string, error) {
	if subject, ok := h.store.LookupToken(token); ok {
		return subject, nil
	}
	id, err := h.provider.ValidateToken(ctx, token)
	if err != nil {
		return "", err
	}
	h.store.CacheToken(token, id.Subject)
	return id.Subject, nil
}

// InvalidateCachedToken delegates cache invalidation to the underlying store.
func (h *Handler) InvalidateCachedToken(token string) {
	h.store.InvalidateCachedToken(token)
}

func isAllowedRedirectHost(hostname string, allowed []string) bool {
	return slices.Contains(allowed, hostname)
}

// joinScopes serializes the provider's scope slice for OAuth token responses.
// The comma delimiter preserves backward compatibility with the previous
// GitHub-coupled implementation, which forwarded GitHub's raw scope string.
// RFC 6749 §3.3 specifies space delimiter; normalization to that form is
// deferred to a separate change to keep this refactor non-breaking.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, ",")
}

func oauthError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}

func jsonError(w http.ResponseWriter, code, description string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             code,
		"error_description": description,
	})
}
