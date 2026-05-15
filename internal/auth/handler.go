package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"log/slog"

	"golang.org/x/sync/singleflight"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

// refreshTokenGracePeriod is the extra lifetime added to refresh tokens beyond
// the access token ExpiresIn, allowing clients to refresh shortly after access
// token expiry without requiring full re-authentication.
const refreshTokenGracePeriod = 30 * 24 * time.Hour

var (
	ErrTokenAudienceMismatch = errors.New("token audience mismatch")
	ErrTokenAudienceMissing  = errors.New("token audience metadata missing")
)

// audienceCheckError wraps audience validation sentinels so middleware can
// distinguish them from generic token errors without importing this package.
type audienceCheckError struct{ inner error }

func (e audienceCheckError) Error() string         { return e.inner.Error() }
func (e audienceCheckError) Unwrap() error         { return e.inner }
func (e audienceCheckError) IsAudienceError() bool { return true }

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
	// AllowedAudiences is the set of RFC 8707 resource indicator values accepted
	// by this gateway. BaseURL is always allowed.
	AllowedAudiences []string
	// TokenAudienceStrict rejects tokens without audience metadata. The default
	// false value is a grace mode for tokens issued before this metadata existed.
	TokenAudienceStrict bool
	// GitHubRefreshEnabled turns on transparent rotation of GitHub-issued access
	// tokens when the upstream provider advertises a refresh token and an
	// expires_in hint (OAuth Apps with "Expire user authorization tokens"
	// enabled). When the upstream is configured for non-expiring tokens this
	// flag has no effect; it is safe to leave on.
	GitHubRefreshEnabled bool
	// GitHubRefreshLeeway is the lead time before access-token expiry at which
	// rotation is attempted on the next ValidateToken call. Defaults to 5 min.
	GitHubRefreshLeeway time.Duration
}

// defaultGitHubRefreshLeeway is the head-start used when GitHubRefreshLeeway
// is unset. Five minutes covers typical clock skew plus the longest realistic
// request batch served by an upstream MCP route while keeping the rotation
// window narrow enough to amortize against the GitHub token endpoint.
const defaultGitHubRefreshLeeway = 5 * time.Minute

// Handler implements the OAuth façade endpoints, delegating provider-specific
// operations to a provider.Provider.
type Handler struct {
	cfg              Config
	provider         provider.Provider
	store            *Store
	allowedAudiences map[string]struct{}
	// rotationGroup serializes concurrent GitHub refresh-token rotations
	// targeting the same access token. Without this, a burst of requests
	// arriving inside the leeway window would race to call the provider's
	// refresh endpoint, wasting upstream quota and risking bad_refresh_token
	// from GitHub's sequential rotation contract.
	rotationGroup singleflight.Group
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
	cfg.AllowedAudiences = normalizeAllowedAudiences(cfg.BaseURL, cfg.AllowedAudiences)
	if len(cfg.AllowedRedirectHosts) == 0 {
		cfg.AllowedRedirectHosts = []string{"localhost", "127.0.0.1", "vscode.dev"}
	}
	if cfg.ExpiresIn <= 0 {
		cfg.ExpiresIn = 90 * 24 * time.Hour
	}

	var ts TokenStore
	var tokensTTL time.Duration
	var storeOpts []StoreOption
	if cfg.TokenStorePath != "" {
		fileStore, err := NewFileTokenStore(cfg.TokenStorePath)
		if err != nil {
			return nil, fmt.Errorf("auth.NewHandler: token store: %w", err)
		}
		ts = fileStore
		tokensTTL = cfg.ExpiresIn

		fileRTS, err := NewFileRefreshTokenStore(cfg.TokenStorePath + ".refresh")
		if err != nil {
			return nil, fmt.Errorf("auth.NewHandler: refresh token store: %w", err)
		}
		storeOpts = append(storeOpts, WithRefreshTokenStore(fileRTS))
	} else {
		ts = NewMemTokenStore()
		tokensTTL = cfg.CacheTTL
		if cfg.TokenAudienceStrict {
			slog.Warn("token_audience_strict is enabled without a persistent token store; " +
				"audience metadata is lost on cache eviction, making affected tokens unusable — " +
				"set token_store_path for durable storage")
		}
	}

	return &Handler{
		cfg:              cfg,
		provider:         p,
		store:            NewStore(cfg.SessionTTL, tokensTTL, ts, storeOpts...),
		allowedAudiences: audienceSet(cfg.AllowedAudiences),
	}, nil
}

// refreshTokenTTL returns the lifetime for gateway-issued refresh tokens.
func (h *Handler) refreshTokenTTL() time.Duration {
	return h.cfg.ExpiresIn + refreshTokenGracePeriod
}

// providerAccessExpiry converts a provider-advertised expires_in duration into
// an absolute time. A zero or negative input means "no expiry hint" and is
// surfaced as a zero time.Time so downstream rotation logic can short-circuit.
func providerAccessExpiry(expiresIn time.Duration) time.Time {
	if expiresIn <= 0 {
		return time.Time{}
	}
	return time.Now().Add(expiresIn)
}

// githubRefreshLeeway returns the configured leeway, falling back to the
// default when unset.
func (h *Handler) githubRefreshLeeway() time.Duration {
	if h.cfg.GitHubRefreshLeeway > 0 {
		return h.cfg.GitHubRefreshLeeway
	}
	return defaultGitHubRefreshLeeway
}

// ProtectedResourceMetadata implements RFC 9728 OAuth 2.0 Protected Resource
// Metadata for the gateway as a whole. MCP clients that receive a 401 with a
// resource_metadata parameter in the WWW-Authenticate header fetch this
// endpoint to discover the gateway's authorization server, enabling
// re-authentication via the OAuth flow instead of falling back to alternative
// auth methods (e.g. gh CLI).
//
// This handler returns the gateway's canonical public URL as the resource
// identifier. For per-route metadata (MCP Authorization Spec 2025-06-18),
// see RouteProtectedResourceMetadata.
func (h *Handler) ProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	h.writePRM(w, h.cfg.BaseURL)
}

// RouteProtectedResourceMetadata returns an HTTP handler that serves an RFC
// 9728 Protected Resource Metadata document for a single route. The resource
// argument MUST be the canonical absolute URL of the route (e.g.
// "https://gateway.example/mcp/copilot-review"); the authorization_servers
// field continues to point at the gateway-wide OAuth authorization server.
//
// Per the MCP Authorization Spec (2025-06-18), each MCP endpoint exposes its
// own PRM at /.well-known/oauth-protected-resource{path-of-resource}. Callers
// register one handler per route alongside the gateway-wide handler.
func (h *Handler) RouteProtectedResourceMetadata(resource string) http.HandlerFunc {
	resource = strings.TrimRight(resource, "/")
	return func(w http.ResponseWriter, r *http.Request) {
		h.writePRM(w, resource)
	}
}

func (h *Handler) writePRM(w http.ResponseWriter, resource string) {
	doc := map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{h.cfg.BaseURL},
		"bearer_methods_supported": []string{"header"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
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
		"resource_parameter_supported":     true,
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
		"grant_types":                []string{"authorization_code", "urn:ietf:params:oauth:grant-type:device_code", "refresh_token"},
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
	audience, audErr := h.resolveRequestedAudience(q["resource"])
	if audErr != nil {
		oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
		return
	}

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

	h.store.SaveSession(state, redirectURI, codeChallenge, audience)

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

	tokens, err := h.provider.ExchangeCode(r.Context(), code)
	if err != nil {
		slog.Error("OAuth token exchange failed", "provider", h.provider.Name(), "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}

	internalCode, err := h.store.CompleteCallback(state, tokens.AccessToken, joinScopes(tokens.Scopes), tokens.RefreshToken, providerAccessExpiry(tokens.AccessTokenExpiresIn))
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
	result, err := h.store.ExchangeCode(
		r.FormValue("code"),
		r.FormValue("redirect_uri"),
		r.FormValue("code_verifier"),
	)
	if err != nil {
		slog.Warn("token exchange rejected", "err", err)
		oauthError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}
	h.store.RegisterTokenAudience(result.AccessToken, result.Audience)
	h.persistProviderRefresh(result.AccessToken, result.ProviderRefreshToken, result.ProviderAccessExpiry)
	refreshToken, rtErr := h.store.CreateRefreshToken(result.AccessToken, result.Audience, h.refreshTokenTTL())
	if rtErr != nil {
		slog.Warn("failed to create refresh token", "err", rtErr)
	}
	h.writeTokenResponse(w, result.AccessToken, result.Scope, refreshToken)
}

// persistProviderRefresh writes upstream provider refresh metadata to the
// token store only when rotation is enabled. The flag is the load-bearing
// switch documented in configuration.md: with it off, the refresh token must
// not be written to disk so the gateway's at-rest credential surface stays
// minimal.
func (h *Handler) persistProviderRefresh(accessToken, refreshToken string, accessExpiry time.Time) {
	if !h.cfg.GitHubRefreshEnabled {
		return
	}
	h.store.RecordProviderRefresh(accessToken, refreshToken, accessExpiry)
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

	// Serialize concurrent GitHub polls for the same device_code. AcquireDevicePolling
	// returns false in two cases: (1) another goroutine is already polling, or (2) the
	// session was consumed/removed between GetDevice and this point.
	// Re-check the session state to return the most accurate OAuth error.
	if !h.store.AcquireDevicePolling(deviceCode) {
		current, ok := h.store.GetDevice(deviceCode)
		if !ok {
			// Session consumed by a concurrent winner.
			oauthError(w, "invalid_grant", "device code already consumed", http.StatusBadRequest)
			return
		}
		if time.Now().After(current.ExpiresAt) {
			oauthError(w, "expired_token", "device code expired", http.StatusBadRequest)
			return
		}
		if current.Status == deviceDenied {
			oauthError(w, "access_denied", "user denied authorization", http.StatusBadRequest)
			return
		}
		// Another goroutine is actively polling; client should retry.
		oauthError(w, "authorization_pending", "polling in progress, please retry", http.StatusBadRequest)
		return
	}
	defer h.store.ReleaseDevicePolling(deviceCode)

	// Status is pending: poll GitHub on behalf of the client.
	result, err := h.pollGitHubDeviceToken(r.Context(), pending.GitHubDevCode)
	if err != nil {
		slog.Error("GitHub device token poll failed", "err", err)
		oauthError(w, "server_error", "upstream error polling GitHub", http.StatusBadGateway)
		return
	}

	switch result.Error {
	case "":
		completed, ok := h.store.AuthorizeAndConsumeDevice(deviceCode, result.AccessToken, result.Scope)
		if !ok {
			oauthError(w, "invalid_grant", "device code already consumed", http.StatusBadRequest)
			return
		}
		h.store.RegisterTokenAudience(result.AccessToken, completed.Audience)
		h.persistProviderRefresh(result.AccessToken, result.RefreshToken, providerAccessExpiry(result.AccessExpiresIn))
		refreshToken, rtErr := h.store.CreateRefreshToken(result.AccessToken, completed.Audience, h.refreshTokenTTL())
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
		slog.Warn("unexpected GitHub device poll error", "err", result.Error)
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
// token response.  The original refresh token is atomically reserved at the
// start, preventing concurrent requests from double-rotating the same token.
// On transient upstream errors or rotation failures the token is restored so
// clients can retry without full re-authentication.
func (h *Handler) tokenRefresh(w http.ResponseWriter, r *http.Request) {
	rt := r.FormValue("refresh_token")
	if rt == "" {
		oauthError(w, "invalid_request", "missing refresh_token", http.StatusBadRequest)
		return
	}

	// Atomically reserve (remove) the token. Concurrent callers presenting the
	// same token will fail here, preventing double-rotation.
	accessToken, audience, rtExpiresAt, err := h.store.ReserveRefreshToken(rt)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenDeleteFailed) {
			slog.Warn("refresh token store failure", "err", err)
			oauthError(w, "temporarily_unavailable", "transient store error, please retry", http.StatusServiceUnavailable)
		} else {
			slog.Warn("refresh token rejected", "err", err)
			oauthError(w, "invalid_grant", "refresh token not found or expired", http.StatusBadRequest)
		}
		return
	}

	// originalAudience holds the audience recorded on the reserved token. It is
	// used for all RestoreRefreshToken calls so that a failure never permanently
	// narrows the old token to a narrower audience.
	originalAudience := audience

	// RFC 8707 §2: optional resource parameter narrows the audience for the
	// re-issued token. The requested audience must be equal to or a strict
	// sub-path of the audience recorded on the original refresh token.
	if resources := r.Form["resource"]; len(resources) > 0 {
		resolved, audErr := h.resolveRequestedAudience(resources)
		if audErr != nil {
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, rtExpiresAt)
			oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
			return
		}
		if !isSubAudience(resolved, originalAudience) {
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, rtExpiresAt)
			oauthError(w, "invalid_target", "resource is not a valid narrowing of the original audience", http.StatusBadRequest)
			return
		}
		audience = resolved
	}

	// Re-validate the underlying token directly against the upstream provider,
	// bypassing the local cache. Using the cache here could allow refresh to
	// succeed for a revoked token until cache expiry.
	id, valErr := h.provider.ValidateToken(r.Context(), accessToken)
	if valErr != nil {
		var upstreamErr *provider.UpstreamError
		if errors.As(valErr, &upstreamErr) {
			slog.Warn("refresh rejected: transient upstream error", "err", valErr)
			// Restore the token with its original audience so the client can retry,
			// potentially with a different resource value.
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, rtExpiresAt)
			oauthError(w, "temporarily_unavailable", "upstream provider unreachable, retry later", http.StatusServiceUnavailable)
		} else {
			slog.Warn("refresh rejected: underlying token invalid", "err", valErr)
			// Token genuinely invalid; do not restore.
			oauthError(w, "invalid_grant", "underlying token no longer valid", http.StatusBadRequest)
		}
		return
	}
	// Re-cache the freshly validated token.
	h.store.CacheToken(accessToken, id.Subject, audience)

	// Issue the rotated refresh token. The original is already consumed (reserved).
	newRT, rtErr := h.store.CreateRefreshToken(accessToken, audience, h.refreshTokenTTL())
	if rtErr != nil {
		slog.Error("failed to rotate refresh token", "err", rtErr)
		// Restore the original token (with its original audience) so the client can retry.
		h.store.RestoreRefreshToken(rt, accessToken, originalAudience, rtExpiresAt)
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
	audience, audErr := h.resolveRequestedAudience(r.Form["resource"])
	if audErr != nil {
		oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
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
	internalCode, err := h.store.CreateDevice(ghResp.DeviceCode, ghResp.UserCode, ghResp.VerificationURI, expiresAt, ghResp.Interval, audience)
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
	AccessToken     string
	Scope           string
	RefreshToken    string
	AccessExpiresIn time.Duration
	Error           string // GitHub error code; empty on success
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
		AccessToken  string `json:"access_token"`
		Scope        string `json:"scope"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return nil, fmt.Errorf("decoding GitHub device token response: %w", err)
	}
	if raw.Error == "" && raw.AccessToken == "" {
		return nil, fmt.Errorf("GitHub device token response: no access_token and no error field")
	}
	return &githubDevicePollResult{
		AccessToken:     raw.AccessToken,
		Scope:           raw.Scope,
		RefreshToken:    raw.RefreshToken,
		AccessExpiresIn: time.Duration(raw.ExpiresIn) * time.Second,
		Error:           raw.Error,
	}, nil
}

// ValidateToken checks the bearer token via the provider (with cache) and
// validates that its stored audience matches the protected resource.
// The returned subject is the Identity.Subject from the provider.
//
// rotatedToken is non-empty when GitHub-issued rotation succeeded on this call.
// Callers (the auth middleware) MUST substitute the original token with the
// rotated value in any subsequent context propagation (proxy forwarding,
// upstream request) so that the upstream sees the fresh access token.
//
//nolint:nonamedreturns // named returns document the rotation contract.
func (h *Handler) ValidateToken(ctx context.Context, token, audience string) (subject, rotatedToken string, err error) {
	audience = normalizeAudience(audience)
	record, cached := h.store.LookupToken(token)
	if cached {
		if err := h.validateAudience(token, record, audience); err != nil {
			return "", "", err
		}
		if rotated, newSubject, ok := h.tryGitHubRotation(ctx, token, record, audience); ok {
			return newSubject, rotated, nil
		}
		if record.Subject != "" {
			return record.Subject, "", nil
		}
	} else if err := h.validateAudience(token, TokenRecord{}, audience); err != nil {
		return "", "", err
	}
	id, valErr := h.provider.ValidateToken(ctx, token)
	if valErr != nil {
		return "", "", valErr
	}
	cacheAudience := ""
	if cached && record.HasAudience(audience) {
		cacheAudience = audience
	}
	h.store.CacheToken(token, id.Subject, cacheAudience)
	return id.Subject, "", nil
}

// rotationResult is the value type stored in the singleflight group so that
// concurrent callers of tryGitHubRotation can share a single rotation outcome.
type rotationResult struct {
	newToken string
	subject  string
	ok       bool
}

// tryGitHubRotation attempts to rotate a GitHub-issued access token when its
// provider expiry is within the configured leeway window.  It returns the new
// token and subject on success; on any failure or when rotation is not
// applicable, the third return is false and the caller continues with the
// original token.
//
// Failures are intentionally non-fatal: rotation is a best-effort optimization,
// and a stale token will surface as an upstream 401 which the existing cache
// invalidation path already handles. Logging "rotation_failed" lets operators
// detect chronic misconfiguration (e.g. revoked refresh token).
//
// The original token's cache entry is **kept** (not invalidated): MCP clients
// continue presenting the original bearer token, and dropping its metadata
// would force them through the provider on the next request — and possibly
// hit 401 once GitHub expires the original. Instead we update the original
// entry's provider refresh metadata to the freshly issued refresh token / new
// expiry so a subsequent in-window request triggers another rotation cleanly.
// The rotated token is cached under its own key so this turn's proxy
// forwarding (and any client that does adopt the rotated value) hits cache.
//
// Concurrent rotation calls for the same access token are collapsed via a
// singleflight group keyed by the token fingerprint. The leader executes the
// provider call; followers receive the leader's result without issuing a
// second refresh request (GitHub treats sequential rotations of the same
// refresh token as a security violation and returns bad_refresh_token).
func (h *Handler) tryGitHubRotation(ctx context.Context, token string, record TokenRecord, audience string) (newToken, subject string, ok bool) {
	if !h.cfg.GitHubRefreshEnabled {
		return "", "", false
	}
	if record.Subject == "" {
		// Without a known subject we would propagate an empty identity into the
		// proxy headers, which downstream services treat as anonymous. Wait
		// until the provider has been queried once and Subject is populated.
		return "", "", false
	}
	if record.ProviderRefreshToken == "" || record.ProviderAccessExpiry.IsZero() {
		return "", "", false
	}
	if time.Until(record.ProviderAccessExpiry) > h.githubRefreshLeeway() {
		return "", "", false
	}

	// Use the full tokenKey (SHA-256 over the raw bearer) for the
	// singleflight key. The shorter tokenFingerprint is only safe for log
	// correlation: collisions in the 8-character prefix would let one
	// caller's rotation result be served to a holder of a different token,
	// which is an auth boundary violation.
	sfKey := tokenKey(token)
	v, _, _ := h.rotationGroup.Do(sfKey, func() (any, error) {
		return h.runGitHubRotation(ctx, token, audience), nil
	})
	// Forget the key so future rotations (after another leeway window passes)
	// are not blocked by a stale completed entry.
	h.rotationGroup.Forget(sfKey)
	res, _ := v.(rotationResult)
	return res.newToken, res.subject, res.ok
}

// runGitHubRotation performs a single rotation attempt under the singleflight
// leader. The caller must guarantee that the gate is on, Subject is known,
// and the cached expiry is within the leeway window.
func (h *Handler) runGitHubRotation(ctx context.Context, token, audience string) rotationResult {
	// Re-read the cache entry: a previous leader on this same key may have
	// just completed a rotation, in which case the expiry is now outside the
	// leeway window and there is nothing more to do.
	record, cached := h.store.LookupToken(token)
	if !cached {
		return rotationResult{}
	}
	if record.ProviderRefreshToken == "" || record.ProviderAccessExpiry.IsZero() {
		return rotationResult{}
	}
	if time.Until(record.ProviderAccessExpiry) > h.githubRefreshLeeway() {
		return rotationResult{}
	}
	tokens, err := h.provider.RefreshToken(ctx, record.ProviderRefreshToken)
	if err != nil {
		if errors.Is(err, provider.ErrRefreshNotSupported) {
			// Permanent: provider does not implement rotation. Clear so
			// subsequent ValidateToken calls do not retry this branch.
			h.store.ClearProviderRefresh(token)
			return rotationResult{}
		}
		var upstreamErr *provider.UpstreamError
		if errors.As(err, &upstreamErr) {
			// Transient (network failure / 5xx). Leave metadata intact so
			// the next request retries — provider will likely recover.
			slog.Warn("rotation_failed",
				"token_hash", tokenFingerprint(token),
				"err", err,
				"action", "retry_next",
			)
			return rotationResult{}
		}
		// Permanent failure (bad_refresh_token, 4xx, malformed response,
		// etc.). Clearing metadata stops every subsequent ValidateToken
		// from re-hitting the provider with the same poisoned refresh
		// token until the cache entry expires.
		slog.Warn("rotation_failed",
			"token_hash", tokenFingerprint(token),
			"err", err,
			"action", "metadata_cleared",
		)
		h.store.ClearProviderRefresh(token)
		return rotationResult{}
	}
	if tokens.AccessToken == "" {
		slog.Warn("rotation_failed",
			"token_hash", tokenFingerprint(token),
			"err", "empty access_token from provider",
			"action", "metadata_cleared",
		)
		h.store.ClearProviderRefresh(token)
		return rotationResult{}
	}
	cacheAudience := ""
	if record.HasAudience(audience) {
		cacheAudience = audience
	}
	newRefresh := tokens.RefreshToken
	if newRefresh == "" {
		// Per RFC 6749 §6 a provider MAY omit a new refresh_token, in which
		// case the previous one remains valid.
		newRefresh = record.ProviderRefreshToken
	}
	newAccessExpiry := providerAccessExpiry(tokens.AccessTokenExpiresIn)
	// Cache the new access token under its own key so that requests adopting
	// the rotated bearer short-circuit on cache hit. We retain the previous
	// subject — provider identity does not change on refresh.
	h.store.CacheToken(tokens.AccessToken, record.Subject, cacheAudience)
	h.persistProviderRefresh(tokens.AccessToken, newRefresh, newAccessExpiry)
	// Update the original entry's provider refresh metadata so the next
	// rotation cycle still works if the client keeps presenting the old
	// bearer (which is the common case — MCP clients do not learn of the
	// rotated value through this flow).
	h.persistProviderRefresh(token, newRefresh, newAccessExpiry)
	slog.Info("github access token rotated",
		"old_token_hash", tokenFingerprint(token),
		"new_token_hash", tokenFingerprint(tokens.AccessToken),
	)
	return rotationResult{
		newToken: tokens.AccessToken,
		subject:  record.Subject,
		ok:       true,
	}
}

// InvalidateCachedToken delegates cache invalidation to the underlying store.
func (h *Handler) InvalidateCachedToken(token string) {
	h.store.InvalidateCachedToken(token)
}

// DelegatedAccessResult is the outcome of EnsureFreshAccessTokenForSubject:
// the raw access token to hand to the calling upstream, the provider-advertised
// expiry (zero when the provider does not advertise one), and the OAuth scopes
// configured for this gateway (best-effort identifier of what the token can do).
type DelegatedAccessResult struct {
	AccessToken          string
	ProviderAccessExpiry time.Time
	Scopes               []string
}

// ErrSubjectNotFound is returned by EnsureFreshAccessTokenForSubject when no
// cached token entry exists for the requested subject. Callers should surface
// this as a 404 to upstream clients.
var ErrSubjectNotFound = errors.New("auth: subject not cached")

// EnsureFreshAccessTokenForSubject returns the latest valid access token for
// the given subject, transparently rotating it when its provider-advertised
// expiry falls within the configured leeway. Used by the Phase B
// delegated-access internal API so background workers (e.g. an upstream MCP
// watcher) can pull a fresh bearer without re-authenticating the user.
//
// Returns ErrSubjectNotFound when no cached token exists for subject. A nil
// error with a non-empty AccessToken means a valid token was returned, even
// if rotation was attempted and failed transiently (the still-valid current
// token is returned). Permanent rotation failures clear the provider refresh
// metadata via the same path used by per-request rotation.
func (h *Handler) EnsureFreshAccessTokenForSubject(ctx context.Context, subject string) (DelegatedAccessResult, error) {
	rawToken, record, ok := h.store.LatestBySubject(subject)
	if !ok {
		return DelegatedAccessResult{}, ErrSubjectNotFound
	}
	// Choose a representative audience: prefer one already on the record
	// (so HasAudience semantics in tryGitHubRotation hit cache), otherwise
	// fall back to the gateway base URL.
	audience := h.cfg.BaseURL
	if len(record.Audiences) > 0 {
		audience = record.Audiences[0]
	}
	if rotated, _, rotatedOK := h.tryGitHubRotation(ctx, rawToken, record, audience); rotatedOK {
		// Re-read the rotated record to pick up its provider expiry.
		if newRec, newOK := h.store.LookupToken(rotated); newOK {
			return DelegatedAccessResult{
				AccessToken:          rotated,
				ProviderAccessExpiry: newRec.ProviderAccessExpiry,
				Scopes:               parseScopes(h.provider.Scopes()),
			}, nil
		}
		return DelegatedAccessResult{
			AccessToken: rotated,
			Scopes:      parseScopes(h.provider.Scopes()),
		}, nil
	}
	return DelegatedAccessResult{
		AccessToken:          rawToken,
		ProviderAccessExpiry: record.ProviderAccessExpiry,
		Scopes:               parseScopes(h.provider.Scopes()),
	}, nil
}

// parseScopes splits a provider scope string (space- or comma-separated) into
// a slice. Empty input yields nil. Whitespace-only tokens are dropped.
func parseScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t'
	})
	if len(fields) == 0 {
		return nil
	}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		f = strings.TrimSpace(f)
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

func (h *Handler) resolveRequestedAudience(resources []string) (string, error) {
	for _, raw := range resources {
		if strings.TrimSpace(raw) == "" {
			return "", fmt.Errorf("resource parameter must not be empty")
		}
	}
	if len(resources) == 0 {
		return h.cfg.BaseURL, nil
	}
	if len(resources) > 1 {
		return "", fmt.Errorf("multiple resource parameters are not supported")
	}
	resource := normalizeAudience(resources[0])
	u, err := url.Parse(resource)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Fragment != "" {
		return "", fmt.Errorf("resource must be an absolute http/https URL without fragment")
	}
	if _, ok := h.allowedAudiences[resource]; !ok {
		return "", fmt.Errorf("resource is not registered with this gateway")
	}
	return resource, nil
}

// validateAudience accepts the requested audience when any recorded audience
// equals it or is a strict ancestor (gateway-wide → route-scoped). The latter
// covers MCP clients (e.g. Codex) that acquire a single gateway-wide token and
// then call multiple authenticated sub-routes; rejecting them due to
// exact-match-only validation would force re-authentication per route, which
// clients in the wild do not implement. Recorded audiences are normalized and
// empty entries skipped so that a stale or malformed cache row cannot bypass
// strict-mode enforcement (isSubAudience treats an empty `original` as a
// wildcard, which is correct for the refresh-token grace path but unsafe
// here).
func (h *Handler) validateAudience(token string, record TokenRecord, audience string) error {
	if audience == "" {
		return nil
	}
	for _, recorded := range record.Audiences {
		recorded = normalizeAudience(recorded)
		if recorded == "" {
			continue
		}
		if isSubAudience(audience, recorded) {
			return nil
		}
	}
	if len(record.Audiences) == 0 {
		if h.cfg.TokenAudienceStrict {
			return audienceCheckError{ErrTokenAudienceMissing}
		}
		slog.Warn("token without audience accepted during grace period",
			"token_hash", tokenFingerprint(token),
			"expected_audience", audience,
		)
		return nil
	}
	return audienceCheckError{ErrTokenAudienceMismatch}
}

func normalizeAllowedAudiences(baseURL string, audiences []string) []string {
	out := make([]string, 0, len(audiences)+1)
	seen := map[string]struct{}{}
	for _, audience := range append([]string{baseURL}, audiences...) {
		audience = normalizeAudience(audience)
		if audience == "" {
			continue
		}
		if _, ok := seen[audience]; ok {
			continue
		}
		seen[audience] = struct{}{}
		out = append(out, audience)
	}
	return out
}

func audienceSet(audiences []string) map[string]struct{} {
	set := make(map[string]struct{}, len(audiences))
	for _, audience := range audiences {
		set[audience] = struct{}{}
	}
	return set
}

func normalizeAudience(audience string) string {
	return strings.TrimRight(strings.TrimSpace(audience), "/")
}

// isSubAudience reports whether requested is equal to or a strict narrowing of
// original (i.e. requested starts with original+"/"). When original is empty
// the token was issued without audience metadata (legacy grace-period token),
// and any registered audience is accepted.
func isSubAudience(requested, original string) bool {
	if original == "" {
		return true
	}
	return requested == original || strings.HasPrefix(requested, original+"/")
}

func tokenFingerprint(token string) string {
	key := tokenKey(token)
	if len(key) <= 8 {
		return key
	}
	return key[:8]
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
