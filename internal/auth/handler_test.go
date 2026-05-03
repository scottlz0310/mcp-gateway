package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

func newTestHandler(t *testing.T) *Handler {
	t.Helper()
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
	})
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func TestDiscovery(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	h.Discovery(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if doc["issuer"] != "http://localhost:8080" {
		t.Errorf("issuer: got %v", doc["issuer"])
	}
	if doc["authorization_endpoint"] != "http://localhost:8080/authorize" {
		t.Errorf("authorization_endpoint: got %v", doc["authorization_endpoint"])
	}
	if doc["token_endpoint"] != "http://localhost:8080/token" {
		t.Errorf("token_endpoint: got %v", doc["token_endpoint"])
	}
}

func TestRegisterReturnsClientID(t *testing.T) {
	h := newTestHandler(t)
	body := `{"redirect_uris":["http://localhost/cb"],"client_name":"test"}`
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusCreated)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["client_id"] != "test-client-id" {
		t.Errorf("client_id: got %v", resp["client_id"])
	}
	if resp["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method: got %v", resp["token_endpoint_auth_method"])
	}
}

func TestRegisterInvalidJSON(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeMissingParams(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing state/redirect_uri: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeInvalidResponseType(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=token&state=s&redirect_uri=http://localhost/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid response_type: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeDisallowedRedirectHost(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=http://evil.example.com/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("disallowed host: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestNewHandlerErrorsOnNilProvider(t *testing.T) {
	_, err := NewHandler(Config{}, nil)
	if err == nil {
		t.Error("expected error for nil provider")
	}
}

func TestAuthorizeRedirectsToGitHub(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=abc123&redirect_uri=http://localhost/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusFound)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://github.com/login/oauth/authorize") {
		t.Errorf("redirect location: %q", loc)
	}
	if !strings.Contains(loc, "client_id=test-client-id") {
		t.Errorf("location missing client_id: %q", loc)
	}
}

func TestDiscoveryIncludesDeviceEndpoints(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	h.Discovery(w, r)

	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if doc["device_authorization_endpoint"] != "http://localhost:8080/device_authorization" {
		t.Errorf("device_authorization_endpoint: got %v", doc["device_authorization_endpoint"])
	}
	grantTypes, ok := doc["grant_types_supported"].([]any)
	if !ok {
		t.Fatal("grant_types_supported is not an array")
	}
	var hasDeviceGrant bool
	for _, g := range grantTypes {
		if g == "urn:ietf:params:oauth:grant-type:device_code" {
			hasDeviceGrant = true
		}
	}
	if !hasDeviceGrant {
		t.Error("grant_types_supported missing device_code grant type")
	}
}

func TestDeviceAuthorizeSuccess(t *testing.T) {
	// Mock GitHub's device code endpoint.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/login/device/code" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{
			"device_code": "gh-dev-code-xyz",
			"user_code": "WDJB-MJHT",
			"verification_uri": "https://github.com/login/device",
			"verification_uri_complete": "https://github.com/login/device?user_code=WDJB-MJHT",
			"expires_in": 900,
			"interval": 5
		}`)
	}))
	defer ghServer.Close()

	origClient := githubClient
	githubClient = ghServer.Client()
	defer func() { githubClient = origClient }()

	h := newTestHandler(t)

	// Override the GitHub device endpoint URL by monkey-patching startGitHubDeviceFlow
	// via a local httptest transport. We can't easily override the URL, so instead we
	// swap the transport to always route to the test server.
	githubClient.Transport = rewriteHostTransport{target: ghServer.URL, inner: ghServer.Client().Transport}

	r := httptest.NewRequest(http.MethodPost, "/device_authorization",
		strings.NewReader("scope=repo"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.DeviceAuthorize(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["user_code"] != "WDJB-MJHT" {
		t.Errorf("user_code: got %v", resp["user_code"])
	}
	if resp["verification_uri"] != "https://github.com/login/device" {
		t.Errorf("verification_uri: got %v", resp["verification_uri"])
	}
	// device_code must be a gateway-internal code, not the GitHub one.
	if resp["device_code"] == "gh-dev-code-xyz" {
		t.Error("device_code must be gateway-internal, not the raw GitHub device_code")
	}
	if resp["device_code"] == nil || resp["device_code"] == "" {
		t.Error("device_code must be non-empty")
	}
}

func TestTokenDeviceGrantPending(t *testing.T) {
	// Mock GitHub's token endpoint returning authorization_pending.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
	}))
	defer ghServer.Close()

	originalTransport := githubClient.Transport
	defer func() { githubClient.Transport = originalTransport }()
	githubClient.Transport = rewriteHostTransport{target: ghServer.URL, inner: ghServer.Client().Transport}

	h := newTestHandler(t)

	// Create a pending device session directly in the store.
	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5)
	if err != nil {
		t.Fatalf("creating device session: %v", err)
	}

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["error"] != "authorization_pending" {
		t.Errorf("error: got %v, want authorization_pending", resp["error"])
	}
}

func TestTokenDeviceGrantSuccess(t *testing.T) {
	// Mock GitHub's token endpoint returning a successful access token.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"access_token":"gha_success_token","scope":"repo,user","token_type":"bearer"}`)
	}))
	defer ghServer.Close()

	originalTransport := githubClient.Transport
	defer func() { githubClient.Transport = originalTransport }()
	githubClient.Transport = rewriteHostTransport{target: ghServer.URL, inner: ghServer.Client().Transport}

	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5)
	if err != nil {
		t.Fatalf("creating device session: %v", err)
	}

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["access_token"] != "gha_success_token" {
		t.Errorf("access_token: got %v", resp["access_token"])
	}
	if resp["refresh_token"] == nil || resp["refresh_token"] == "" {
		t.Error("expected refresh_token in device grant success response")
	}
}

// TestTokenRefreshSuccess verifies that a valid refresh token returns the
// underlying access token and a rotated refresh token.
func TestTokenRefreshSuccess(t *testing.T) {
	// Mock GitHub user API so ValidateToken succeeds.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"alice","name":"Alice"}`)
	}))
	defer ghServer.Close()

	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		UserAPI:      ghServer.URL + "/user",
		HTTPClient:   ghServer.Client(),
	})
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Seed a refresh token for an existing access token.
	rt, err := h.store.CreateRefreshToken("gha_existing_token", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["access_token"] != "gha_existing_token" {
		t.Errorf("access_token: got %v", resp["access_token"])
	}
	newRT, _ := resp["refresh_token"].(string)
	if newRT == "" {
		t.Fatal("expected rotated refresh_token in response")
	}
	if newRT == rt {
		t.Error("rotated refresh_token must differ from original")
	}
	// Original refresh token must be consumed (one-time use).
	if _, err := h.store.UseRefreshToken(rt); err == nil {
		t.Error("original refresh token must be invalidated after use")
	}
}

// TestTokenRefreshMissingToken verifies that omitting refresh_token returns 400.
func TestTokenRefreshMissingToken(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader("grant_type=refresh_token"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_request" {
		t.Errorf("error: got %v", resp["error"])
	}
}

// TestTokenRefreshUnknown verifies that an unknown refresh_token returns invalid_grant.
func TestTokenRefreshUnknown(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader("grant_type=refresh_token&refresh_token=bogus"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_grant" {
		t.Errorf("error: got %v, want invalid_grant", resp["error"])
	}
}

// TestTokenRefreshUpstreamErrorPreservesToken verifies that when the upstream
// provider returns a transient error, the refresh token is NOT consumed and
// the response is 503 temporarily_unavailable.
func TestTokenRefreshUpstreamErrorPreservesToken(t *testing.T) {
	// Mock GitHub user API returning 503.
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream error", http.StatusServiceUnavailable)
	}))
	defer ghServer.Close()

	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		UserAPI:      ghServer.URL + "/user",
		HTTPClient:   ghServer.Client(),
	})
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rt, err := h.store.CreateRefreshToken("gha_token", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want 503; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "temporarily_unavailable" {
		t.Errorf("error: got %v, want temporarily_unavailable", resp["error"])
	}
	// Refresh token must still be valid for retry.
	if _, err := h.store.PeekRefreshToken(rt); err != nil {
		t.Errorf("refresh token must be preserved on upstream error: %v", err)
	}
}

// TestTokenRefreshConcurrentSameToken verifies that two concurrent requests
// presenting the same refresh token result in exactly one success and one
// invalid_grant, enforcing atomic one-time-use / rotation semantics.
func TestTokenRefreshConcurrentSameToken(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"alice","name":"Alice"}`)
	}))
	defer ghServer.Close()

	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		UserAPI:      ghServer.URL + "/user",
		HTTPClient:   ghServer.Client(),
	})
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	rt, err := h.store.CreateRefreshToken("gha_concurrent_token", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	var wg sync.WaitGroup
	results := make([]int, 2)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			rec := httptest.NewRecorder()
			h.Token(rec, req)
			results[idx] = rec.Code
		}(i)
	}
	wg.Wait()

	okCount, badCount := 0, 0
	for _, code := range results {
		switch code {
		case http.StatusOK:
			okCount++
		case http.StatusBadRequest:
			badCount++
		}
	}
	if okCount != 1 || badCount != 1 {
		t.Errorf("expected 1 success and 1 invalid_grant; got status codes %v", results)
	}
}

// TestDiscoveryAdvertisesRefreshTokenGrant verifies that the Discovery metadata
// includes refresh_token in grant_types_supported.
func TestDiscoveryAdvertisesRefreshTokenGrant(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	w := httptest.NewRecorder()

	h.Discovery(w, r)

	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding discovery: %v", err)
	}
	grants, ok := doc["grant_types_supported"].([]any)
	if !ok {
		t.Fatal("grant_types_supported not a slice")
	}
	var hasRefresh bool
	for _, g := range grants {
		if g == "refresh_token" {
			hasRefresh = true
		}
	}
	if !hasRefresh {
		t.Error("grant_types_supported must include refresh_token")
	}
}

// TestHandlerRefreshTokenSurvivesRestart verifies that a file-backed refresh
// token store wired by NewHandler persists refresh tokens across handler
// re-instantiation (simulating a gateway restart with the same token store
// path).  Write-failure handling is exercised at the unit level in
// TestFileRefreshTokenStorePersistence (tokenstore_test.go).
func TestHandlerRefreshTokenSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	newHandlerWithPath := func(t *testing.T, path string) *Handler {
		t.Helper()
		p := provider.NewGitHub(provider.GitHubConfig{
			ClientID:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectURI:  "http://localhost:8080/callback",
			Scopes:       "repo,user",
		})
		h, err := NewHandler(Config{
			BaseURL:        "http://localhost:8080",
			SessionTTL:     10 * time.Minute,
			CacheTTL:       5 * time.Minute,
			ExpiresIn:      90 * 24 * time.Hour,
			TokenStorePath: path,
		}, p)
		if err != nil {
			t.Fatalf("NewHandler: %v", err)
		}
		return h
	}

	h1 := newHandlerWithPath(t, storePath)
	rt, err := h1.store.CreateRefreshToken("gha_access_token", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	// Re-instantiate handler (simulating restart) with the same store path.
	h2 := newHandlerWithPath(t, storePath)
	accessToken, err := h2.store.PeekRefreshToken(rt)
	if err != nil {
		t.Fatalf("PeekRefreshToken after restart: %v", err)
	}
	if accessToken != "gha_access_token" {
		t.Errorf("access token after restart: got %q, want %q", accessToken, "gha_access_token")
	}

	// Verify the .refresh sibling file was created alongside the configured path.
	refreshPath := storePath + ".refresh"
	if _, statErr := os.Stat(refreshPath); statErr != nil {
		t.Errorf(".refresh sibling file not created: %v", statErr)
	}
}

// rewriteHostTransport rewrites the target host of outbound HTTP requests,
// allowing tests to intercept external HTTP calls.
type rewriteHostTransport struct {
	target string
	inner  http.RoundTripper
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	parsed, err := url.Parse(t.target)
	if err != nil {
		return nil, err
	}
	req = req.Clone(req.Context())
	req.URL.Scheme = parsed.Scheme
	req.URL.Host = parsed.Host
	req.Host = parsed.Host
	if t.inner != nil {
		return t.inner.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
