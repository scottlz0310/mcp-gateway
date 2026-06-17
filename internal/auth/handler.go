package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
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
	// ResourceAudienceMap maps resource parameter values (route names) to the aud
	// claim to set in issued access tokens. Built from Route.RequiredAudience at
	// startup by cmd/server. When a /token request includes resource=<key>, the
	// corresponding value is used as the JWT aud claim.
	// Example: {"mcp": "mcp-server", "external-mcp": "external-mcp"}
	ResourceAudienceMap map[string]string
	// AllowedRedirectSchemes is the set of custom URL schemes (RFC 8252) permitted
	// as redirect_uri in addition to http and https. When empty, defaults to
	// ["antigravity", "antigravity-insiders"]. Set explicitly to override.
	AllowedRedirectSchemes []string
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
	// OIDCPrivateKey is the RSA private key used to sign ID tokens.
	// When nil, a transient in-memory key is generated and a warning is logged.
	OIDCPrivateKey *rsa.PrivateKey
}

// defaultGitHubRefreshLeeway is the head-start used when GitHubRefreshLeeway
// is unset. Five minutes covers typical clock skew plus the longest realistic
// request batch served by an upstream MCP route while keeping the rotation
// window narrow enough to amortize against the GitHub token endpoint.
const defaultGitHubRefreshLeeway = 5 * time.Minute

// Handler implements the OAuth façade endpoints, delegating provider-specific
// operations to a provider.Provider.
type Handler struct {
	cfg        Config
	provider   provider.Provider
	store      *Store
	privateKey *rsa.PrivateKey
	audit      authaudit.Recorder
	// rotationGroup serializes concurrent GitHub refresh-token rotations
	// targeting the same access token. Without this, a burst of requests
	// arriving inside the leeway window would race to call the provider's
	// refresh endpoint, wasting upstream quota and risking bad_refresh_token
	// from GitHub's sequential rotation contract.
	rotationGroup singleflight.Group
}

// HandlerOption は任意の auth handler integration を設定する。
type HandlerOption func(*Handler)

// WithAuditRecorder は OAuth 監査ログ永続化と直近失敗診断を有効化する。
// recorder は事前に初期化済みでなければならない。
func WithAuditRecorder(recorder authaudit.Recorder) HandlerOption {
	return func(h *Handler) {
		h.audit = recorder
	}
}

// NewHandler creates a new OAuth Handler with the given configuration and provider.
// It returns an error if the provider is nil or if the persistent token store
// cannot be initialized.
//
// When cfg.TokenStorePath is non-empty, validated tokens are stored durably in a
// JSON file so that MCP clients do not need to re-authenticate after gateway
// restarts. Tokens are stored with TTL equal to cfg.ExpiresIn (default 90 days).
// When cfg.TokenStorePath is empty, an in-memory store is used (TTL = cfg.CacheTTL).
func NewHandler(cfg Config, p provider.Provider, opts ...HandlerOption) (*Handler, error) {
	if p == nil {
		return nil, fmt.Errorf("auth.NewHandler: provider must not be nil")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	if len(cfg.AllowedRedirectHosts) == 0 {
		cfg.AllowedRedirectHosts = []string{"localhost", "127.0.0.1", "vscode.dev", "antigravity.google"}
	}
	if len(cfg.AllowedRedirectSchemes) == 0 {
		cfg.AllowedRedirectSchemes = []string{"antigravity", "antigravity-insiders"}
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

		sqliteRTS, err := NewSQLiteRefreshTokenStore(cfg.TokenStorePath + ".refresh.db")
		if err != nil {
			return nil, fmt.Errorf("auth.NewHandler: refresh token store: %w", err)
		}
		if err := migrateFileRefreshTokenStore(cfg.TokenStorePath+".refresh", sqliteRTS); err != nil {
			return nil, fmt.Errorf("auth.NewHandler: migrating legacy refresh token store: %w", err)
		}
		storeOpts = append(storeOpts, WithRefreshTokenStore(sqliteRTS))
	} else {
		ts = NewMemTokenStore()
		tokensTTL = cfg.CacheTTL
		if cfg.TokenAudienceStrict {
			slog.Warn("token_audience_strict is enabled without a persistent token store; " +
				"audience metadata is lost on cache eviction, making affected tokens unusable — " +
				"set token_store_path for durable storage")
		}
	}

	privateKey := cfg.OIDCPrivateKey
	if privateKey == nil {
		slog.Warn("OIDC signing key is not persisted; generating a random key. Sessions will become invalid across restarts.")
		var err error
		privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("auth.NewHandler: generating signing key: %w", err)
		}
	}

	handler := &Handler{
		cfg:        cfg,
		provider:   p,
		store:      NewStore(cfg.SessionTTL, tokensTTL, ts, storeOpts...),
		privateKey: privateKey,
	}
	for _, opt := range opts {
		opt(handler)
	}
	return handler, nil
}

func (h *Handler) auditSuccess(phase, message string, httpStatus int) {
	h.recordAudit(authaudit.Event{
		Phase:      phase,
		Provider:   h.provider.Name(),
		Result:     "success",
		HTTPStatus: httpStatus,
		Message:    message,
	})
}

func (h *Handler) auditFailure(phase, errorClass, message string, err error, httpStatus int, tokenHash string) {
	oauthCode, providerStatus, transient := provider.ErrorDetails(err)
	if providerStatus != 0 {
		httpStatus = providerStatus
	}
	if transient {
		errorClass = "provider_unavailable"
	} else if oauthCode != "" && errorClass == "provider_error" {
		errorClass = "provider_rejected"
	}
	h.recordAudit(authaudit.Event{
		Phase:      phase,
		Provider:   h.provider.Name(),
		Result:     "failure",
		ErrorClass: errorClass,
		OAuthError: oauthCode,
		HTTPStatus: httpStatus,
		Message:    message,
		TokenHash:  tokenHash,
	})
}

func (h *Handler) recordAudit(event authaudit.Event) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Record(event); err != nil {
		slog.Error("auth audit persistence failed",
			"phase", event.Phase,
			"result", event.Result,
			"err", err,
		)
	}
}

// RecentAuthFailures は internal 診断 endpoint 向けに最新順の snapshot を返す。
func (h *Handler) RecentAuthFailures() []authaudit.Event {
	if h.audit == nil {
		return nil
	}
	return h.audit.RecentFailures()
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
		h.auditFailure("authorize", "invalid_target", "authorization target rejected", audErr, http.StatusBadRequest, "")
		oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		h.auditFailure("authorize", "unsupported_response_type", "authorization response type rejected", nil, http.StatusBadRequest, "")
		oauthError(w, "unsupported_response_type", "response_type must be 'code'", http.StatusBadRequest)
		return
	}
	if state == "" || redirectURI == "" {
		h.auditFailure("authorize", "invalid_request", "authorization request missing required parameters", nil, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "missing state or redirect_uri", http.StatusBadRequest)
		return
	}
	if codeChallenge != "" && codeChallengeMethod != "S256" {
		h.auditFailure("authorize", "invalid_request", "authorization PKCE method rejected", nil, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "code_challenge_method must be S256", http.StatusBadRequest)
		return
	}

	parsedRedirect, err := url.Parse(redirectURI)
	if err != nil || parsedRedirect.Scheme == "" || parsedRedirect.Host == "" || parsedRedirect.Fragment != "" {
		h.auditFailure("authorize", "invalid_request", "authorization redirect URI rejected", err, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "invalid redirect_uri: must be an absolute URI without fragment", http.StatusBadRequest)
		return
	}
	switch parsedRedirect.Scheme {
	case "http", "https":
		if !isAllowedRedirectHost(parsedRedirect.Hostname(), h.cfg.AllowedRedirectHosts) {
			h.auditFailure("authorize", "invalid_request", "authorization redirect host rejected", nil, http.StatusBadRequest, "")
			oauthError(w, "invalid_request", "redirect_uri host not permitted", http.StatusBadRequest)
			return
		}
	default:
		// RFC 8252: custom URL scheme for native apps (e.g. antigravity://oauth-callback)
		if !isAllowedRedirectScheme(parsedRedirect.Scheme, h.cfg.AllowedRedirectSchemes) {
			h.auditFailure("authorize", "invalid_request", "authorization redirect scheme rejected", nil, http.StatusBadRequest, "")
			oauthError(w, "invalid_request", "redirect_uri scheme not permitted", http.StatusBadRequest)
			return
		}
	}

	h.store.SaveSession(state, redirectURI, codeChallenge, audience)
	h.auditSuccess("authorize", "authorization redirect created", http.StatusFound)

	http.Redirect(w, r, h.provider.AuthorizeURL(state, codeChallenge), http.StatusFound)
}

// Callback receives the provider's authorization code and exchanges it for
// an access token via the Provider implementation.
func (h *Handler) Callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	code := q.Get("code")
	state := q.Get("state")
	if oauthCode := provider.NormalizeOAuthErrorCode(q.Get("error")); oauthCode != "" {
		h.recordAudit(authaudit.Event{
			Phase:      "callback",
			Provider:   h.provider.Name(),
			Result:     "failure",
			ErrorClass: "provider_rejected",
			OAuthError: oauthCode,
			HTTPStatus: http.StatusBadRequest,
			Message:    "provider authorization callback rejected",
		})
		http.Error(w, "authorization failed", http.StatusBadRequest)
		return
	}

	if code == "" || state == "" {
		h.auditFailure("callback", "invalid_request", "authorization callback missing required parameters", nil, http.StatusBadRequest, "")
		http.Error(w, "missing code or state", http.StatusBadRequest)
		return
	}
	if !h.store.HasSession(state) {
		h.auditFailure("callback", "invalid_state", "authorization callback state rejected", nil, http.StatusBadRequest, "")
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	tokens, err := h.provider.ExchangeCode(r.Context(), code)
	if err != nil {
		h.auditFailure("token_exchange", "provider_error", "provider token exchange failed", err, http.StatusBadGateway, "")
		slog.Error("OAuth token exchange failed", "provider", h.provider.Name(), "err", err)
		http.Error(w, "token exchange failed", http.StatusBadGateway)
		return
	}
	h.auditSuccess("token_exchange", "provider token exchange succeeded", http.StatusOK)

	// Resolve provider identity early to get the Subject claim
	id, err := h.provider.ValidateToken(r.Context(), tokens.AccessToken)
	if err != nil {
		h.auditFailure("identity_resolution", "provider_error", "provider identity resolution failed", err, http.StatusBadGateway, tokenFingerprint(tokens.AccessToken))
		slog.Error("OAuth identity resolution failed during callback", "provider", h.provider.Name(), "err", err)
		http.Error(w, "identity resolution failed", http.StatusBadGateway)
		return
	}
	h.auditSuccess("identity_resolution", "provider identity resolved", http.StatusOK)

	internalCode, err := h.store.CompleteCallback(state, tokens.AccessToken, joinScopes(tokens.Scopes), tokens.RefreshToken, providerAccessExpiry(tokens.AccessTokenExpiresIn), id.Subject)
	if err != nil {
		h.auditFailure("callback", "store_error", "authorization callback session completion failed", err, http.StatusBadRequest, "")
		slog.Error("session completion failed", "err", err)
		http.Error(w, "invalid state", http.StatusBadRequest)
		return
	}

	sess := h.store.lookupByCode(internalCode)
	if sess == nil {
		h.auditFailure("callback", "internal_error", "authorization callback session was unavailable", nil, http.StatusInternalServerError, "")
		http.Error(w, "session lost", http.StatusInternalServerError)
		return
	}

	redirect, _ := url.Parse(sess.RedirectURI)
	rq := redirect.Query()
	rq.Set("code", internalCode)
	rq.Set("state", state)
	redirect.RawQuery = rq.Encode()

	h.auditSuccess("callback", "authorization callback completed", http.StatusFound)
	http.Redirect(w, r, redirect.String(), http.StatusFound)
}

// Token dispatches to the appropriate grant handler based on grant_type.
func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		h.auditFailure("token_exchange", "invalid_request", "token request body rejected", err, http.StatusBadRequest, "")
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
		h.auditFailure("token_exchange", "unsupported_grant_type", "token grant type rejected", nil, http.StatusBadRequest, "")
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
		h.auditFailure("token_exchange", "invalid_grant", "authorization code exchange rejected", err, http.StatusBadRequest, "")
		slog.Warn("token exchange rejected", "err", err)
		oauthError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
		return
	}

	if h.isBuiltinMode() {
		// builtin mode: discard GitHub access token, issue gateway-signed JWT instead.
		// GitHub token was used only for identity resolution in Callback(); it must not
		// reach the client.
		gatewayToken, genErr := h.generateGatewayAccessToken(result.Subject, result.Audience)
		if genErr != nil {
			h.auditFailure("token_exchange", "server_error", "gateway access token generation failed", genErr, http.StatusInternalServerError, "")
			slog.Error("gateway access token generation failed", "err", genErr)
			oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
			return
		}
		h.store.CacheToken(gatewayToken, result.Subject, result.Audience)
		familyID, fidErr := generateCode()
		if fidErr != nil {
			slog.Warn("failed to generate refresh token family ID", "err", fidErr)
			familyID = ""
		}
		refreshToken, rtErr := h.store.CreateRefreshToken(gatewayToken, result.Audience, familyID, h.refreshTokenTTL())
		if rtErr != nil {
			slog.Warn("failed to create refresh token", "err", rtErr)
		}
		h.writeTokenResponse(w, gatewayToken, result.Scope, refreshToken, result.Subject)
		h.auditSuccess("token_exchange", "authorization code exchange completed (builtin)", http.StatusOK)
		return
	}

	h.store.CacheToken(result.AccessToken, result.Subject, result.Audience)
	h.persistProviderRefresh(result.AccessToken, result.ProviderRefreshToken, result.ProviderAccessExpiry)
	familyID, fidErr := generateCode()
	if fidErr != nil {
		slog.Warn("failed to generate refresh token family ID", "err", fidErr)
		familyID = ""
	}
	refreshToken, rtErr := h.store.CreateRefreshToken(result.AccessToken, result.Audience, familyID, h.refreshTokenTTL())
	if rtErr != nil {
		slog.Warn("failed to create refresh token", "err", rtErr)
	}
	h.writeTokenResponse(w, result.AccessToken, result.Scope, refreshToken, result.Subject)
	h.auditSuccess("token_exchange", "authorization code exchange completed", http.StatusOK)
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
		h.auditFailure("token_exchange", "invalid_request", "device token request missing device code", nil, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "missing device_code", http.StatusBadRequest)
		return
	}

	pending, ok := h.store.GetDevice(deviceCode)
	if !ok {
		h.auditFailure("token_exchange", "invalid_grant", "device token grant was not found", nil, http.StatusBadRequest, "")
		oauthError(w, "invalid_grant", "device code not found", http.StatusBadRequest)
		return
	}
	if time.Now().After(pending.ExpiresAt) {
		h.auditFailure("token_exchange", "token_expired", "device token grant expired", nil, http.StatusBadRequest, "")
		oauthError(w, "expired_token", "device code expired", http.StatusBadRequest)
		return
	}

	switch pending.Status {
	case deviceDenied:
		h.auditFailure("token_exchange", "access_denied", "device token grant denied", nil, http.StatusBadRequest, "")
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
		h.auditFailure("token_exchange", "provider_error", "provider device token exchange failed", err, http.StatusBadGateway, "")
		slog.Error("GitHub device token poll failed", "err", err)
		oauthError(w, "server_error", "upstream error polling GitHub", http.StatusBadGateway)
		return
	}

	switch result.Error {
	case "":
		// Resolve provider identity early to get the Subject claim
		id, valErr := h.provider.ValidateToken(r.Context(), result.AccessToken)
		if valErr != nil {
			h.auditFailure("identity_resolution", "provider_error", "device grant identity resolution failed", valErr, http.StatusBadGateway, tokenFingerprint(result.AccessToken))
			slog.Error("Identity resolution failed during device grant callback", "err", valErr)
			oauthError(w, "server_error", "failed to resolve identity", http.StatusBadGateway)
			return
		}
		h.auditSuccess("identity_resolution", "device grant identity resolved", http.StatusOK)
		completed, ok := h.store.AuthorizeAndConsumeDevice(deviceCode, result.AccessToken, result.Scope)
		if !ok {
			h.auditFailure("token_exchange", "invalid_grant", "device token grant was already consumed", nil, http.StatusBadRequest, "")
			oauthError(w, "invalid_grant", "device code already consumed", http.StatusBadRequest)
			return
		}
		h.store.CacheToken(result.AccessToken, id.Subject, completed.Audience)
		h.persistProviderRefresh(result.AccessToken, result.RefreshToken, providerAccessExpiry(result.AccessExpiresIn))
		deviceFamilyID, deviceFidErr := generateCode()
		if deviceFidErr != nil {
			slog.Warn("failed to generate refresh token family ID (device)", "err", deviceFidErr)
			deviceFamilyID = ""
		}
		refreshToken, rtErr := h.store.CreateRefreshToken(result.AccessToken, completed.Audience, deviceFamilyID, h.refreshTokenTTL())
		if rtErr != nil {
			slog.Warn("failed to create refresh token", "err", rtErr)
		}
		h.writeTokenResponse(w, result.AccessToken, result.Scope, refreshToken, id.Subject)
		h.auditSuccess("token_exchange", "device token exchange completed", http.StatusOK)
	case "authorization_pending":
		oauthError(w, "authorization_pending", "user has not yet authorized the device", http.StatusBadRequest)
	case "slow_down":
		// RFC 8628 §3.5: client must increase polling interval by 5 seconds
		oauthError(w, "slow_down", "polling too frequently, increase interval by 5 seconds", http.StatusBadRequest)
	case "expired_token":
		h.auditFailure("token_exchange", "token_expired", "provider device token expired", nil, http.StatusBadRequest, "")
		oauthError(w, "expired_token", "device code expired on GitHub", http.StatusBadRequest)
	case "access_denied":
		h.store.DenyDevice(deviceCode)
		h.recordAudit(authaudit.Event{
			Phase:      "token_exchange",
			Provider:   h.provider.Name(),
			Result:     "failure",
			ErrorClass: "access_denied",
			OAuthError: "access_denied",
			HTTPStatus: http.StatusBadRequest,
			Message:    "provider device authorization denied",
		})
		oauthError(w, "access_denied", "user denied authorization", http.StatusBadRequest)
	default:
		h.recordAudit(authaudit.Event{
			Phase:      "token_exchange",
			Provider:   h.provider.Name(),
			Result:     "failure",
			ErrorClass: "provider_rejected",
			OAuthError: provider.NormalizeOAuthErrorCode(result.Error),
			HTTPStatus: http.StatusBadGateway,
			Message:    "provider device token exchange rejected",
		})
		slog.Warn("unexpected GitHub device poll error", "err", result.Error)
		oauthError(w, "server_error", "unexpected upstream error: "+result.Error, http.StatusBadGateway)
	}
}

func (h *Handler) writeTokenResponse(w http.ResponseWriter, token, scope, refreshToken string, subject string) {
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
	if subject != "" && (strings.Contains(scope, "openid") || h.provider.Name() == "oidc" || h.isBuiltinMode()) {
		idToken, err := h.generateIDToken(h.cfg.BaseURL, subject, h.provider.ClientID())
		if err == nil {
			resp["id_token"] = idToken
		} else {
			slog.Error("failed to generate id_token", "err", err)
		}
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
		h.auditFailure("refresh", "invalid_request", "refresh request missing refresh token", nil, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "missing refresh_token", http.StatusBadRequest)
		return
	}

	// Atomically reserve (remove) the token. Concurrent callers presenting the
	// same token will fail here, preventing double-rotation.
	// On reuse detection (revoked token replay), ReserveRefreshToken revokes the
	// entire family before returning an error.
	accessToken, audience, familyID, rtExpiresAt, err := h.store.ReserveRefreshToken(rt)
	if err != nil {
		if errors.Is(err, ErrRefreshTokenDeleteFailed) {
			h.auditFailure("refresh", "store_error", "refresh token store unavailable", err, http.StatusServiceUnavailable, "")
			slog.Warn("refresh token store failure", "err", err)
			oauthError(w, "temporarily_unavailable", "transient store error, please retry", http.StatusServiceUnavailable)
		} else {
			h.auditFailure("refresh", "invalid_grant", "refresh token rejected", err, http.StatusBadRequest, "")
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
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
			h.auditFailure("refresh", "invalid_target", "refresh token target rejected", audErr, http.StatusBadRequest, tokenFingerprint(accessToken))
			oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
			return
		}
		if !isSubAudience(resolved, originalAudience) {
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
			h.auditFailure("refresh", "invalid_target", "refresh token target widening rejected", nil, http.StatusBadRequest, tokenFingerprint(accessToken))
			oauthError(w, "invalid_target", "resource is not a valid narrowing of the original audience", http.StatusBadRequest)
			return
		}
		audience = resolved
	}

	if h.isBuiltinMode() {
		// builtin mode: verify the existing gateway JWT locally to extract subject,
		// then issue a new gateway JWT. GitHub API is not consulted.
		sub, _, jwtErr := h.verifyGatewayJWT(accessToken)
		if jwtErr != nil {
			h.auditFailure("refresh", "invalid_grant", "refresh token gateway JWT invalid", jwtErr, http.StatusBadRequest, tokenFingerprint(accessToken))
			slog.Warn("refresh rejected: gateway JWT invalid", "err", jwtErr)
			oauthError(w, "invalid_grant", "underlying token no longer valid", http.StatusBadRequest)
			return
		}
		newGatewayToken, genErr := h.generateGatewayAccessToken(sub, audience)
		if genErr != nil {
			h.auditFailure("refresh", "server_error", "gateway token generation failed during refresh", genErr, http.StatusInternalServerError, tokenFingerprint(accessToken))
			slog.Error("gateway access token generation failed during refresh", "err", genErr)
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
			oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
			return
		}
		h.store.CacheToken(newGatewayToken, sub, audience)
		// Propagate the same familyID so the token lineage remains traceable.
		newRT, rtErr := h.store.CreateRefreshToken(newGatewayToken, audience, familyID, h.refreshTokenTTL())
		if rtErr != nil {
			h.auditFailure("refresh", "store_error", "refresh token rotation failed", rtErr, http.StatusInternalServerError, tokenFingerprint(newGatewayToken))
			slog.Error("failed to rotate refresh token (builtin)", "err", rtErr)
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
			oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
			return
		}
		h.writeTokenResponse(w, newGatewayToken, "", newRT, sub)
		h.auditSuccess("refresh", "refresh token exchange completed (builtin)", http.StatusOK)
		return
	}

	// Re-validate the underlying token directly against the upstream provider,
	// bypassing the local cache. Using the cache here could allow refresh to
	// succeed for a revoked token until cache expiry.
	id, valErr := h.provider.ValidateToken(r.Context(), accessToken)
	if valErr != nil {
		var upstreamErr *provider.UpstreamError
		if errors.As(valErr, &upstreamErr) {
			h.auditFailure("refresh", "provider_error", "refresh identity validation unavailable", valErr, http.StatusServiceUnavailable, tokenFingerprint(accessToken))
			slog.Warn("refresh rejected: transient upstream error", "err", valErr)
			// Restore the token with its original audience so the client can retry,
			// potentially with a different resource value.
			h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
			oauthError(w, "temporarily_unavailable", "upstream provider unreachable, retry later", http.StatusServiceUnavailable)
		} else {
			h.auditFailure("refresh", "invalid_grant", "refresh token underlying access token invalid", valErr, http.StatusBadRequest, tokenFingerprint(accessToken))
			slog.Warn("refresh rejected: underlying token invalid", "err", valErr)
			// Token genuinely invalid; do not restore.
			oauthError(w, "invalid_grant", "underlying token no longer valid", http.StatusBadRequest)
		}
		return
	}
	// Re-cache the freshly validated token.
	h.store.CacheToken(accessToken, id.Subject, audience)

	// Issue the rotated refresh token propagating familyID for reuse tracking.
	newRT, rtErr := h.store.CreateRefreshToken(accessToken, audience, familyID, h.refreshTokenTTL())
	if rtErr != nil {
		h.auditFailure("refresh", "store_error", "refresh token rotation failed", rtErr, http.StatusInternalServerError, tokenFingerprint(accessToken))
		slog.Error("failed to rotate refresh token", "err", rtErr)
		// Restore the original token (with its original audience) so the client can retry.
		h.store.RestoreRefreshToken(rt, accessToken, originalAudience, familyID, rtExpiresAt)
		oauthError(w, "server_error", "internal error", http.StatusInternalServerError)
		return
	}

	h.writeTokenResponse(w, accessToken, "", newRT, id.Subject)
	h.auditSuccess("refresh", "refresh token exchange completed", http.StatusOK)
}

// DeviceAuthorize handles POST /device_authorization (RFC 8628).
// It requests a device code from GitHub and returns the user_code and verification_uri to the client.
// client_secret is NOT required for GitHub's Device Flow.
func (h *Handler) DeviceAuthorize(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		h.auditFailure("authorize", "invalid_request", "device authorization request body rejected", err, http.StatusBadRequest, "")
		oauthError(w, "invalid_request", "malformed request body", http.StatusBadRequest)
		return
	}
	audience, audErr := h.resolveRequestedAudience(r.Form["resource"])
	if audErr != nil {
		h.auditFailure("authorize", "invalid_target", "device authorization target rejected", audErr, http.StatusBadRequest, "")
		oauthError(w, "invalid_target", audErr.Error(), http.StatusBadRequest)
		return
	}

	// Always use configured scopes to prevent clients from escalating to broader permissions.
	scope := h.provider.Scopes()

	ghResp, err := h.startGitHubDeviceFlow(r.Context(), scope)
	if err != nil {
		h.auditFailure("authorize", "provider_error", "provider device authorization start failed", err, http.StatusBadGateway, "")
		slog.Error("GitHub device flow start failed", "err", err)
		oauthError(w, "server_error", "failed to start device flow with GitHub", http.StatusBadGateway)
		return
	}

	expiresAt := time.Now().Add(time.Duration(ghResp.ExpiresIn) * time.Second)
	internalCode, err := h.store.CreateDevice(ghResp.DeviceCode, ghResp.UserCode, ghResp.VerificationURI, expiresAt, ghResp.Interval, audience)
	if err != nil {
		h.auditFailure("authorize", "store_error", "device authorization session creation failed", err, http.StatusInternalServerError, "")
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
	h.auditSuccess("authorize", "device authorization started", http.StatusOK)
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
		return nil, githubDeviceHTTPError(resp, "device_authorization")
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
		return nil, githubDeviceHTTPError(resp, "device_token")
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
		Error:           provider.NormalizeOAuthErrorCode(raw.Error),
	}, nil
}

func githubDeviceHTTPError(resp *http.Response, operation string) error {
	var payload struct {
		Error string `json:"error"`
	}
	_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&payload)
	oauthErr := &provider.OAuthError{
		Provider:   "github",
		Operation:  operation,
		Code:       provider.NormalizeOAuthErrorCode(payload.Error),
		HTTPStatus: resp.StatusCode,
		Transient:  resp.StatusCode >= 500 || githubRateLimited(resp),
	}
	if oauthErr.Transient {
		return &provider.UpstreamError{Err: oauthErr}
	}
	return oauthErr
}

func githubRateLimited(resp *http.Response) bool {
	if resp.StatusCode == http.StatusTooManyRequests {
		return true
	}
	return resp.StatusCode == http.StatusForbidden &&
		(strings.TrimSpace(resp.Header.Get("Retry-After")) != "" ||
			strings.TrimSpace(resp.Header.Get("X-RateLimit-Remaining")) == "0")
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
			if !record.RotationPermanentlyFailed {
				// Re-seed the subject index on a cache hit. After process
				// restart with a persistent TokenStore, subjectIndex (in-memory
				// only) is empty even though tokens are readable from disk;
				// otherwise the Phase B /internal/v1/whoami would keep
				// returning subject_not_found until the cache TTL expires.
				// Permanently-failed tokens are intentionally excluded: they
				// must not be re-inserted into the subject index or
				// EnsureFreshAccessTokenForSubject would serve a dead bearer
				// via the lenient (no-metadata) branch after a restart.
				h.store.RefreshSubjectIndex(record.Subject, token, record.ExpiresAt)
			}
			return record.Subject, "", nil
		}
	}

	// builtin mode: validate gateway-issued JWT locally without calling GitHub API.
	// Must be checked before validateAudience because the token store has no audience
	// record on cache miss; validateAudience(token, TokenRecord{}, audience) would
	// erroneously reject valid tokens when TokenAudienceStrict is enabled.
	if h.isBuiltinMode() {
		sub, tokenAud, jwtErr := h.verifyGatewayJWT(token)
		if jwtErr != nil {
			h.auditFailure("identity_resolution", "invalid_token", "gateway JWT verification failed", jwtErr, http.StatusUnauthorized, tokenFingerprint(token))
			return "", "", jwtErr
		}
		// Validate that the JWT audience matches the requested resource.
		// normalizeAudience("") returns "" which means any audience is accepted.
		if audience != "" && normalizeAudience(tokenAud) != audience {
			err := audienceCheckError{ErrTokenAudienceMismatch}
			h.auditFailure("identity_resolution", "invalid_token", "gateway JWT audience mismatch", err, http.StatusUnauthorized, tokenFingerprint(token))
			return "", "", err
		}
		// Cache with the audience from the JWT so subsequent hits can validate it.
		cacheAudience := tokenAud
		if audience != "" {
			cacheAudience = audience
		}
		h.store.CacheToken(token, sub, cacheAudience)
		h.auditSuccess("identity_resolution", "gateway JWT verified", http.StatusOK)
		return sub, "", nil
	}

	if err := h.validateAudience(token, TokenRecord{}, audience); err != nil {
		return "", "", err
	}

	id, valErr := h.provider.ValidateToken(ctx, token)
	if valErr != nil {
		h.auditFailure("identity_resolution", "provider_error", "bearer identity resolution failed", valErr, http.StatusUnauthorized, tokenFingerprint(token))
		return "", "", valErr
	}
	cacheAudience := ""
	if cached && record.HasAudience(audience) {
		cacheAudience = audience
	}
	h.store.CacheToken(token, id.Subject, cacheAudience)
	h.auditSuccess("identity_resolution", "bearer identity resolved", http.StatusOK)
	return id.Subject, "", nil
}

// rotationResult is the value type stored in the singleflight group so that
// concurrent callers of tryGitHubRotation can share a single rotation outcome.
//
// noOp signals that runGitHubRotation entered under the gate, but the second
// (authoritative) cache re-read showed that rotation was no longer needed —
// either another goroutine just rotated successfully and moved the expiry
// outside the leeway window, or the cache entry was invalidated entirely.
// Callers that distinguish "rotation failed" from "no rotation required"
// (notably the delegated-access path) use this to avoid surfacing a 502 when
// a concurrent rotation already produced a fresh cached bearer.
type rotationResult struct {
	newToken string
	subject  string
	ok       bool
	noOp     bool
}

// rotationAttemptResult mirrors rotationResult but additionally records
// whether the leader actually invoked the provider refresh. attempted=true
// means all preconditions (gate enabled, known subject, refresh metadata
// present, expiry within leeway) were satisfied and we issued a refresh
// request — regardless of whether the rotation succeeded. This lets callers
// distinguish "we tried and could not produce a fresh token" (502) from
// "rotation was not applicable for this token" (lenient fallthrough).
type rotationAttemptResult struct {
	rotationResult
	attempted bool
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
	res := h.tryGitHubRotationWithAttempt(ctx, token, record, audience)
	return res.newToken, res.subject, res.ok
}

// tryGitHubRotationWithAttempt is the underlying implementation that also
// reports whether a rotation was actually attempted. Callers that need to
// distinguish "applicable-but-failed" from "not applicable" (notably the
// internal delegated-access path) use this directly. Public callers can
// keep using tryGitHubRotation.
func (h *Handler) tryGitHubRotationWithAttempt(ctx context.Context, token string, record TokenRecord, audience string) rotationAttemptResult {
	if !h.cfg.GitHubRefreshEnabled {
		return rotationAttemptResult{}
	}
	if record.Subject == "" {
		// Without a known subject we would propagate an empty identity into the
		// proxy headers, which downstream services treat as anonymous. Wait
		// until the provider has been queried once and Subject is populated.
		return rotationAttemptResult{}
	}
	if record.ProviderRefreshToken == "" || record.ProviderAccessExpiry.IsZero() {
		return rotationAttemptResult{}
	}
	if time.Until(record.ProviderAccessExpiry) > h.githubRefreshLeeway() {
		return rotationAttemptResult{}
	}

	// All preconditions satisfied — from here on a refresh request is (or
	// was concurrently) issued, so callers see attempted=true even if the
	// provider call ultimately fails.
	//
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
	return rotationAttemptResult{rotationResult: res, attempted: true}
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
		return rotationResult{noOp: true}
	}
	if record.ProviderRefreshToken == "" || record.ProviderAccessExpiry.IsZero() {
		// Metadata cleared (either by a previous permanent failure on this
		// same call's first attempt, or by a concurrent permanent failure).
		// Not a "successful concurrent rotation" — caller must treat this
		// as a real failure.
		return rotationResult{}
	}
	if time.Until(record.ProviderAccessExpiry) > h.githubRefreshLeeway() {
		// Concurrent rotation moved the expiry outside the leeway window.
		// The cached bearer at `token` was just refreshed; signal noOp so
		// the caller returns it instead of surfacing a spurious 502.
		return rotationResult{noOp: true}
	}
	tokens, err := h.provider.RefreshToken(ctx, record.ProviderRefreshToken)
	if err != nil {
		if errors.Is(err, provider.ErrRefreshNotSupported) {
			h.auditFailure("rotation", "not_supported", "provider token rotation is not supported", err, 0, tokenFingerprint(token))
			// Permanent: provider does not implement rotation. Clear so
			// subsequent ValidateToken calls do not retry this branch.
			h.store.ClearProviderRefresh(token)
			return rotationResult{}
		}
		var upstreamErr *provider.UpstreamError
		if errors.As(err, &upstreamErr) {
			h.auditFailure("rotation", "provider_error", "provider token rotation unavailable", err, 0, tokenFingerprint(token))
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
		// token until the cache entry expires. Marking the token as
		// permanently failed additionally causes EnsureFreshAccessToken-
		// ForSubject's lenient branch to return ErrRotationFailed instead
		// of the (now-dead) cached bearer.
		h.auditFailure("rotation", "provider_error", "provider token rotation rejected", err, 0, tokenFingerprint(token))
		slog.Warn("rotation_failed",
			"token_hash", tokenFingerprint(token),
			"err", err,
			"action", "metadata_cleared",
		)
		h.store.MarkRotationPermanentlyFailed(token)
		return rotationResult{}
	}
	if tokens.AccessToken == "" {
		h.auditFailure("rotation", "malformed_response", "provider token rotation returned no access token", nil, 0, tokenFingerprint(token))
		slog.Warn("rotation_failed",
			"token_hash", tokenFingerprint(token),
			"err", "empty access_token from provider",
			"action", "metadata_cleared",
		)
		h.store.MarkRotationPermanentlyFailed(token)
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
	h.recordAudit(authaudit.Event{
		Phase:      "rotation",
		Provider:   h.provider.Name(),
		Result:     "success",
		HTTPStatus: http.StatusOK,
		Message:    "provider access token rotated",
		TokenHash:  tokenFingerprint(tokens.AccessToken),
	})
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

// ErrRotationFailed is returned by EnsureFreshAccessTokenForSubject when the
// cached token is within the rotation leeway window, the refresh gate is on,
// the subject and provider refresh metadata are present, and a refresh
// request was issued but did not yield a fresh token (transient provider
// error, an upstream rejection, or — within the same call — a permanent
// failure that cleared metadata mid-flight). Also returned by the lenient
// branch when a prior permanent rotation failure was recorded for the token
// (IsRotationPermanentlyFailed), preventing a dead bearer from being handed
// to callers. Callers should surface this as a 502-class upstream failure:
// returning the cached token in this state would hand the caller a credential
// it cannot use.
var ErrRotationFailed = errors.New("auth: rotation failed for delegated access")

// EnsureFreshAccessTokenForSubject returns the latest valid access token for
// the given subject, transparently rotating it when its provider-advertised
// expiry falls within the configured leeway. Used by the Phase B
// delegated-access internal API so background workers (e.g. an upstream MCP
// watcher) can pull a fresh bearer without re-authenticating the user.
//
// Returns ErrSubjectNotFound when no cached token exists for subject (including
// after a permanent rotation failure: MarkRotationPermanentlyFailed removes the
// token from the subject index so this function never reaches the lenient branch
// for permanently-failed tokens — ErrSubjectNotFound is returned instead).
// Returns ErrRotationFailed when all rotation preconditions were
// satisfied (GitHubRefreshEnabled, known subject, provider refresh
// metadata present, expiry within leeway) and a refresh request was
// issued but produced no fresh token. A nil error with a non-empty
// AccessToken means a usable token was returned: a freshly rotated
// bearer, a cached token whose expiry is comfortably outside the
// leeway window, or — for entries that do not satisfy the rotation
// preconditions (refresh gate disabled, classic non-expiring PATs) —
// the cached token as-is. The latter "lenient" branch deliberately
// does not raise ErrRotationFailed: there is no rotation contract for
// those entries to violate.
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
	rotRes := h.tryGitHubRotationWithAttempt(ctx, rawToken, record, audience)
	if rotRes.ok {
		// Re-read the rotated record to pick up its provider expiry.
		if newRec, newOK := h.store.LookupToken(rotRes.newToken); newOK {
			return DelegatedAccessResult{
				AccessToken:          rotRes.newToken,
				ProviderAccessExpiry: newRec.ProviderAccessExpiry,
				Scopes:               parseScopes(h.provider.Scopes()),
			}, nil
		}
		return DelegatedAccessResult{
			AccessToken: rotRes.newToken,
			Scopes:      parseScopes(h.provider.Scopes()),
		}, nil
	}
	if rotRes.attempted {
		if rotRes.noOp {
			// Concurrent rotation already produced a fresh bearer (or the
			// cache entry was invalidated). Re-read the authoritative
			// record: if it is still present with metadata, treat the
			// raw token as freshly rotated. If it disappeared entirely,
			// fall through to ErrRotationFailed — we cannot vouch for
			// freshness without a record.
			if freshRec, stillCached := h.store.LookupToken(rawToken); stillCached {
				return DelegatedAccessResult{
					AccessToken:          rawToken,
					ProviderAccessExpiry: freshRec.ProviderAccessExpiry,
					Scopes:               parseScopes(h.provider.Scopes()),
				}, nil
			}
		}
		// All preconditions for rotation were satisfied (refresh gate on,
		// known subject, metadata present, expiry within leeway) but the
		// refresh attempt did not yield a fresh token. The cached bearer
		// is at or past its useful life; do not hand it out.
		//
		// Note: we deliberately do NOT recompute the leeway window here
		// against the post-rotation timestamp. Basing the decision on
		// rotRes.attempted instead of re-evaluating time.Until guarantees
		// the same input that drove tryGitHubRotation drives this
		// fallthrough — no boundary race between the two checks.
		return DelegatedAccessResult{}, ErrRotationFailed
	}
	// Lenient branch: rotation was not applicable — either the refresh
	// gate is disabled, no provider refresh metadata is present, or the
	// cached expiry is comfortably outside the leeway window. Re-read the
	// record so we report the most current expiry hint (it may have
	// changed under us).
	freshRec, stillCached := h.store.LookupToken(rawToken)
	if !stillCached {
		// Concurrent invalidation between LatestBySubject and now.
		return DelegatedAccessResult{}, ErrSubjectNotFound
	}
	// Gap 2 fix: a prior permanent rotation failure (bad_refresh_token,
	// revoked credentials) cleared the provider refresh metadata and set
	// the permanently-failed flag. The cached bearer is at or past its
	// useful life; do not hand it out even though no fresh rotation was
	// attempted in this call.
	if h.store.IsRotationPermanentlyFailed(rawToken) {
		return DelegatedAccessResult{}, ErrRotationFailed
	}
	return DelegatedAccessResult{
		AccessToken:          rawToken,
		ProviderAccessExpiry: freshRec.ProviderAccessExpiry,
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
		return "mcp-gateway", nil
	}
	if len(resources) > 1 {
		return "", fmt.Errorf("multiple resource parameters are not supported")
	}
	resource := strings.TrimSpace(resources[0])
	// "mcp-gateway" is the built-in default audience; always resolvable.
	if resource == "mcp-gateway" {
		return "mcp-gateway", nil
	}
	if aud, ok := h.cfg.ResourceAudienceMap[resource]; ok {
		return aud, nil
	}
	return "", fmt.Errorf("resource %q is not registered with this gateway", resource)
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


func normalizeAudience(audience string) string {
	return strings.TrimRight(strings.TrimSpace(audience), "/")
}

// isSubAudience reports whether requested is equal to or a valid narrowing of
// original. For URL-based audiences, narrowing means a strict path prefix.
// For the identifier "mcp-gateway", any audience is a valid narrowing because
// it represents gateway-wide access. When original is empty the token was
// issued without audience metadata (legacy grace-period token), and any
// audience is accepted.
func isSubAudience(requested, original string) bool {
	if original == "" {
		return true
	}
	if requested == original {
		return true
	}
	// Gateway-wide audience may be narrowed to any per-route audience on refresh.
	if original == "mcp-gateway" {
		return true
	}
	return strings.HasPrefix(requested, original+"/")
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

func isAllowedRedirectScheme(scheme string, allowed []string) bool {
	return slices.Contains(allowed, scheme)
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

// OIDCDiscovery returns OpenID Connect Discovery metadata.
func (h *Handler) OIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	doc := map[string]any{
		"issuer":                                h.cfg.BaseURL,
		"authorization_endpoint":                h.cfg.BaseURL + "/authorize",
		"token_endpoint":                        h.cfg.BaseURL + "/token",
		"userinfo_endpoint":                     h.cfg.BaseURL + "/userinfo",
		"jwks_uri":                              h.cfg.BaseURL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "name", "preferred_username", "email"},
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// JWKS returns the JSON Web Key Set containing the gateway's public key for signature verification.
func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	if h.privateKey == nil {
		http.Error(w, "JWKS not configured", http.StatusInternalServerError)
		return
	}
	pub := h.privateKey.Public().(*rsa.PublicKey)

	// Encode N and E
	nStr := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())

	eBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(eBytes, uint32(pub.E))
	start := 0
	for start < len(eBytes) && eBytes[start] == 0 {
		start++
	}
	eStr := base64.RawURLEncoding.EncodeToString(eBytes[start:])

	jwk := map[string]any{
		"kty": "RSA",
		"use": "sig",
		"alg": "RS256",
		"kid": "gateway-key-1",
		"n":   nStr,
		"e":   eStr,
	}

	doc := map[string]any{
		"keys": []any{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// UserInfo returns OIDC UserInfo claims for the authenticated user.
func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	authHeader := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(authHeader) <= len(prefix) || !strings.HasPrefix(authHeader, prefix) {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token", error_description="Missing or malformed Bearer token"`)
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"Missing or malformed Bearer token"}`))
		return
	}
	token := authHeader[len(prefix):]

	// Validate the gateway token. Audience is empty for userinfo endpoint.
	subject, _, err := h.ValidateToken(r.Context(), token, "")
	if err != nil {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer error="invalid_token", error_description=%q`, err.Error()))
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = fmt.Fprintf(w, `{"error":"invalid_token","error_description":%q}`, err.Error())
		return
	}

	doc := map[string]any{
		"sub":                subject,
		"name":               subject,
		"preferred_username": subject,
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(doc)
}

// isBuiltinMode reports whether the handler operates in builtin mode, where
// the gateway issues its own RS256 JWTs instead of forwarding provider tokens.
func (h *Handler) isBuiltinMode() bool {
	return h.provider.Name() == "builtin"
}

// generateGatewayAccessToken creates a signed RS256 JWT suitable for use as
// the client-facing access_token in builtin mode. Unlike generateIDToken it
// uses h.cfg.ExpiresIn for the expiry so the lifetime matches the token store TTL.
func (h *Handler) generateGatewayAccessToken(subject, audience string) (string, error) {
	if h.privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "gateway-key-1",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	now := time.Now()
	expiresIn := h.cfg.ExpiresIn
	if expiresIn <= 0 {
		expiresIn = 90 * 24 * time.Hour
	}
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return "", fmt.Errorf("generating JWT ID: %w", err)
	}
	payload := map[string]any{
		"iss": h.cfg.BaseURL,
		"sub": subject,
		"aud": audience,
		"iat": now.Unix(),
		"exp": now.Add(expiresIn).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jtiBytes),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, h.privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("signing gateway access token: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

// verifyGatewayJWT verifies a gateway-issued RS256 JWT and returns the subject
// and audience claims. It validates alg, signature, exp (required), and sub.
// Audience matching against the request resource is the caller's responsibility.
func (h *Handler) verifyGatewayJWT(token string) (subject, audience string, err error) {
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		return "", "", fmt.Errorf("malformed JWT: expected 3 parts")
	}

	// Validate header: alg must be RS256.
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", "", fmt.Errorf("JWT header decode: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return "", "", fmt.Errorf("JWT header parse: %w", err)
	}
	if header.Alg != "RS256" {
		return "", "", fmt.Errorf("JWT alg must be RS256, got %q", header.Alg)
	}

	signingInput := parts[0] + "." + parts[1]
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return "", "", fmt.Errorf("JWT signature decode: %w", err)
	}
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)
	if err := rsa.VerifyPKCS1v15(&h.privateKey.PublicKey, crypto.SHA256, hashed, sigBytes); err != nil {
		return "", "", fmt.Errorf("JWT signature invalid: %w", err)
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", "", fmt.Errorf("JWT payload decode: %w", err)
	}
	var claims struct {
		Sub string `json:"sub"`
		Aud string `json:"aud"`
		Exp int64  `json:"exp"`
	}
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return "", "", fmt.Errorf("JWT payload parse: %w", err)
	}
	if claims.Sub == "" {
		return "", "", fmt.Errorf("JWT missing sub claim")
	}
	// exp is required in gateway-issued JWTs; absence or zero is rejected.
	if claims.Exp <= 0 || time.Now().Unix() > claims.Exp {
		return "", "", fmt.Errorf("JWT expired or missing exp claim")
	}
	return claims.Sub, claims.Aud, nil
}

// generateIDToken creates a signed RS256 JWT for the given subject.
func (h *Handler) generateIDToken(issuer, subject, clientID string) (string, error) {
	if h.privateKey == nil {
		return "", fmt.Errorf("private key is nil")
	}

	// 1. Header
	header := map[string]string{
		"alg": "RS256",
		"typ": "JWT",
		"kid": "gateway-key-1",
	}
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	// 2. Payload
	now := time.Now().Unix()
	payload := map[string]any{
		"iss": issuer,
		"sub": subject,
		"aud": clientID,
		"iat": now,
		"exp": now + 3600, // 1 hour
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	// 3. Sign
	signingInput := headerB64 + "." + payloadB64
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, h.privateKey, crypto.SHA256, hashed)
	if err != nil {
		return "", fmt.Errorf("signing failed: %w", err)
	}
	sigB64 := base64.RawURLEncoding.EncodeToString(sigBytes)

	return signingInput + "." + sigB64, nil
}

// Close releases resources held by the handler (e.g. the SQLite refresh token store).
func (h *Handler) Close() error {
	return h.store.Close()
}
