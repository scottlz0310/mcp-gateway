package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func newTestHandler() *Handler {
	return NewHandler(Config{
		GitHubClientID:     "test-client-id",
		GitHubClientSecret: "test-client-secret",
		BaseURL:            "http://localhost:8080",
		Scopes:             "repo,user",
		SessionTTL:         10 * time.Minute,
		CacheTTL:           5 * time.Minute,
		ExpiresIn:          90 * 24 * time.Hour,
	})
}

func TestDiscovery(t *testing.T) {
	h := newTestHandler()
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
	h := newTestHandler()
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
	h := newTestHandler()
	r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader("not json"))
	w := httptest.NewRecorder()

	h.Register(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeMissingParams(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("missing state/redirect_uri: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeInvalidResponseType(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=token&state=s&redirect_uri=http://localhost/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid response_type: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeDisallowedRedirectHost(t *testing.T) {
	h := newTestHandler()
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=http://evil.example.com/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Errorf("disallowed host: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestAuthorizeRedirectsToGitHub(t *testing.T) {
	h := newTestHandler()
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
	h := newTestHandler()
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

	h := newTestHandler()

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

	h := newTestHandler()

	// Create a pending device session directly in the store.
	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, _ := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5)

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

	h := newTestHandler()

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, _ := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5)

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
}

// rewriteHostTransport redirects all requests to the given target URL,
// allowing tests to intercept external HTTP calls.
type rewriteHostTransport struct {
	target string
	inner  http.RoundTripper
}

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	parsed, _ := url.Parse(t.target)
	req = req.Clone(req.Context())
	req.URL.Scheme = parsed.Scheme
	req.URL.Host = parsed.Host
	if t.inner != nil {
		return t.inner.RoundTrip(req)
	}
	return http.DefaultTransport.RoundTrip(req)
}
