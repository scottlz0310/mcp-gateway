package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
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

func TestProtectedResourceMetadata(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	h.ProtectedResourceMetadata(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type: got %q, want %q", ct, "application/json")
	}
	var doc map[string]any
	if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if doc["resource"] != "http://localhost:8080" {
		t.Errorf("resource: got %v, want http://localhost:8080", doc["resource"])
	}
	servers, ok := doc["authorization_servers"].([]any)
	if !ok || len(servers) == 0 || servers[0] != "http://localhost:8080" {
		t.Errorf("authorization_servers: got %v", doc["authorization_servers"])
	}
	bearerMethods, ok := doc["bearer_methods_supported"].([]any)
	if !ok || len(bearerMethods) == 0 || bearerMethods[0] != "header" {
		t.Errorf("bearer_methods_supported: got %v", doc["bearer_methods_supported"])
	}
}

// TestRouteProtectedResourceMetadata verifies that per-route PRM documents
// (MCP Authorization Spec 2025-06-18) emit the route's canonical URL as the
// resource identifier while the authorization_servers field continues to
// point at the gateway-wide OAuth server.
func TestRouteProtectedResourceMetadata(t *testing.T) {
	h := newTestHandler(t)
	cases := []struct {
		name     string
		resource string
		want     string
	}{
		{name: "subroute", resource: "http://localhost:8080/mcp/copilot-review", want: "http://localhost:8080/mcp/copilot-review"},
		{name: "trailing slash trimmed", resource: "http://localhost:8080/mcp/foo/", want: "http://localhost:8080/mcp/foo"},
		{name: "root prefix", resource: "http://localhost:8080/mcp", want: "http://localhost:8080/mcp"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := h.RouteProtectedResourceMetadata(tc.resource)
			r := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource/mcp/x", nil)
			w := httptest.NewRecorder()

			handler(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want %d", w.Code, http.StatusOK)
			}
			if ct := w.Header().Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type: got %q, want %q", ct, "application/json")
			}
			var doc map[string]any
			if err := json.NewDecoder(w.Body).Decode(&doc); err != nil {
				t.Fatalf("decoding response: %v", err)
			}
			if doc["resource"] != tc.want {
				t.Errorf("resource: got %v, want %s", doc["resource"], tc.want)
			}
			servers, ok := doc["authorization_servers"].([]any)
			if !ok || len(servers) == 0 || servers[0] != "http://localhost:8080" {
				t.Errorf("authorization_servers: got %v, want gateway BaseURL", doc["authorization_servers"])
			}
		})
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

func TestAuthorizeResourceAudienceStoredOnToken(t *testing.T) {
	const routeAudience = "http://localhost:8080/mcp/foo"
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ScopesValue:   "repo,user",
		ExchangeCodeFunc: func(_ context.Context, _ string) (string, []string, error) {
			return "opaque-route-token", []string{"repo", "user"}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:          "http://localhost:8080",
		SessionTTL:       10 * time.Minute,
		CacheTTL:         5 * time.Minute,
		ExpiresIn:        90 * 24 * time.Hour,
		AllowedAudiences: []string{routeAudience},
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=state-aud&redirect_uri=http://localhost/cb&resource="+url.QueryEscape(routeAudience), nil)
	authRec := httptest.NewRecorder()
	h.Authorize(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize status: got %d, want 302; body: %s", authRec.Code, authRec.Body.String())
	}

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=provider-code&state=state-aud", nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback status: got %d, want 302; body: %s", cbRec.Code, cbRec.Body.String())
	}
	redirectURL, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parsing callback redirect: %v", err)
	}
	internalCode := redirectURL.Query().Get("code")
	if internalCode == "" {
		t.Fatal("callback redirect missing internal code")
	}

	body := "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%2Fcb&code=" + url.QueryEscape(internalCode)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status: got %d, want 200; body: %s", tokenRec.Code, tokenRec.Body.String())
	}

	rec, ok := h.store.LookupToken("opaque-route-token")
	if !ok {
		t.Fatal("issued token should be registered in token store")
	}
	if !rec.HasAudience(routeAudience) {
		t.Fatalf("token audiences: got %#v, want %q", rec.Audiences, routeAudience)
	}
	subject, err := h.ValidateToken(context.Background(), "opaque-route-token", routeAudience)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if subject != "alice" {
		t.Errorf("subject: got %q, want alice", subject)
	}
}

func TestAuthorizeRejectsUnknownResource(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=http://localhost/cb&resource=http%3A%2F%2Flocalhost%3A8080%2Fmcp%2Fmissing", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %q, want invalid_target", resp["error"])
	}
}

func TestValidateTokenAudienceMismatch(t *testing.T) {
	h := newTestHandler(t)
	h.store.RegisterTokenAudience("route-token", "http://localhost:8080/mcp/a")
	h.store.CacheToken("route-token", "alice", "")

	_, err := h.ValidateToken(context.Background(), "route-token", "http://localhost:8080/mcp/b")
	if !errors.Is(err, ErrTokenAudienceMismatch) {
		t.Fatalf("ValidateToken err: got %v, want ErrTokenAudienceMismatch", err)
	}
}

// TestValidateTokenAudiencePrefixMatching covers the gateway-wide → route-scoped
// acceptance path required by MCP clients (e.g. Codex) that acquire a single
// token at the public URL and then call multiple authenticated sub-routes.
func TestValidateTokenAudiencePrefixMatching(t *testing.T) {
	cases := []struct {
		name      string
		recorded  string
		requested string
		wantErr   error
	}{
		{
			name:      "broader_recorded_accepts_narrower_route",
			recorded:  "http://localhost:8080",
			requested: "http://localhost:8080/mcp/github",
		},
		{
			name:      "exact_match",
			recorded:  "http://localhost:8080/mcp/github",
			requested: "http://localhost:8080/mcp/github",
		},
		{
			name:      "sibling_route_rejected",
			recorded:  "http://localhost:8080/mcp/github",
			requested: "http://localhost:8080/mcp/copilot-review",
			wantErr:   ErrTokenAudienceMismatch,
		},
		{
			name:      "narrower_recorded_rejects_broader_request",
			recorded:  "http://localhost:8080/mcp/github",
			requested: "http://localhost:8080",
			wantErr:   ErrTokenAudienceMismatch,
		},
		{
			name:      "same_prefix_different_path_rejected",
			recorded:  "http://localhost:8080/mcp/github",
			requested: "http://localhost:8080/mcp/github-other",
			wantErr:   ErrTokenAudienceMismatch,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t)
			h.store.RegisterTokenAudience("token", tc.recorded)
			h.store.CacheToken("token", "alice", "")

			subject, err := h.ValidateToken(context.Background(), "token", tc.requested)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("got err %v, want nil", err)
				}
				if subject != "alice" {
					t.Errorf("subject: got %q, want alice", subject)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("got err %v, want %v", err, tc.wantErr)
			}
		})
	}
}

func TestValidateTokenLegacyGraceAndStrictModes(t *testing.T) {
	const audience = "http://localhost:8080/mcp/foo"
	var calls int
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			calls++
			return provider.Identity{Provider: "mock", Subject: "legacy-user"}, nil
		},
	}
	grace, err := NewHandler(Config{
		BaseURL:          "http://localhost:8080",
		SessionTTL:       10 * time.Minute,
		CacheTTL:         5 * time.Minute,
		AllowedAudiences: []string{audience},
	}, p)
	if err != nil {
		t.Fatalf("NewHandler grace: %v", err)
	}
	subject, err := grace.ValidateToken(context.Background(), "legacy-token", audience)
	if err != nil {
		t.Fatalf("grace ValidateToken: %v", err)
	}
	if subject != "legacy-user" {
		t.Errorf("subject: got %q", subject)
	}
	if calls != 1 {
		t.Errorf("provider calls in grace mode: got %d, want 1", calls)
	}
	rec, ok := grace.store.LookupToken("legacy-token")
	if !ok || rec.Subject != "legacy-user" || len(rec.Audiences) != 0 {
		t.Fatalf("legacy cache record: got %#v ok=%v", rec, ok)
	}

	strict, err := NewHandler(Config{
		BaseURL:             "http://localhost:8080",
		SessionTTL:          10 * time.Minute,
		CacheTTL:            5 * time.Minute,
		AllowedAudiences:    []string{audience},
		TokenAudienceStrict: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler strict: %v", err)
	}
	_, err = strict.ValidateToken(context.Background(), "legacy-token", audience)
	if !errors.Is(err, ErrTokenAudienceMissing) {
		t.Fatalf("strict ValidateToken err: got %v, want ErrTokenAudienceMissing", err)
	}
	if calls != 1 {
		t.Errorf("strict mode should reject before provider validation; calls=%d", calls)
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
	internalCode, err := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5, "http://localhost:8080")
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

func TestTokenDeviceGrantConcurrentPollingDoesNotSlowDown(t *testing.T) {
	var upstreamCalls int32
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&upstreamCalls, 1)
		time.Sleep(50 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
	}))
	defer ghServer.Close()

	originalTransport := githubClient.Transport
	defer func() { githubClient.Transport = originalTransport }()
	githubClient.Transport = rewriteHostTransport{target: ghServer.URL, inner: ghServer.Client().Transport}

	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5, "http://localhost:8080/mcp")
	if err != nil {
		t.Fatalf("creating device session: %v", err)
	}

	const requests = 5
	start := make(chan struct{})
	results := make(chan map[string]any, requests)
	var wg sync.WaitGroup

	for range requests {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
			r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()

			h.Token(w, r)

			if w.Code != http.StatusBadRequest {
				t.Errorf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
			}
			var resp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
				t.Errorf("decoding response: %v", err)
				return
			}
			results <- resp
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	var slowDown int
	for resp := range results {
		if resp["error"] == "slow_down" {
			slowDown++
		}
	}
	if slowDown != 0 {
		t.Fatalf("expected no slow_down responses, got %d", slowDown)
	}
	if got := atomic.LoadInt32(&upstreamCalls); got != 1 {
		t.Fatalf("expected exactly one upstream poll, got %d", got)
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
	internalCode, err := h.store.CreateDevice("gh-dev-code", "WDJB-MJHT", "https://github.com/login/device", expiresAt, 5, "http://localhost:8080")
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
	rt, err := h.store.CreateRefreshToken("gha_existing_token", "http://localhost:8080/mcp", h.refreshTokenTTL())
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

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080/mcp", h.refreshTokenTTL())
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

	rt, err := h.store.CreateRefreshToken("gha_concurrent_token", "http://localhost:8080/mcp", h.refreshTokenTTL())
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
	rt, err := h1.store.CreateRefreshToken("gha_access_token", "http://localhost:8080/mcp", 24*time.Hour)
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

// ── error-injection helpers ───────────────────────────────────────────────────

// deleteFailRefreshStore wraps a real in-memory store for all operations
// except Delete, which always returns an error.  This causes
// ReserveRefreshToken to return ErrRefreshTokenDeleteFailed.
type deleteFailRefreshStore struct {
	inner *memRefreshTokenStore
}

func (d *deleteFailRefreshStore) Save(rt, at, aud string, exp time.Time) error {
	return d.inner.Save(rt, at, aud, exp)
}
func (d *deleteFailRefreshStore) Lookup(rt string) (string, string, time.Time, bool) {
	return d.inner.Lookup(rt)
}
func (d *deleteFailRefreshStore) Delete(_ string) error { return fmt.Errorf("disk I/O error") }
func (d *deleteFailRefreshStore) Sweep() error          { return d.inner.Sweep() }

// TestTokenRefreshDeleteFailed503 verifies that when the refresh token store
// fails to delete the token during rotation (ErrRefreshTokenDeleteFailed),
// the handler returns 503 temporarily_unavailable instead of 400 invalid_grant.
func TestTokenRefreshDeleteFailed503(t *testing.T) {
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
	})

	inner := &memRefreshTokenStore{entries: make(map[string]memRTEntry)}
	failStore := &deleteFailRefreshStore{inner: inner}
	_ = inner.Save("test-rt", "test-at", "http://localhost:8080/mcp", time.Now().Add(time.Hour))

	store := NewStore(time.Minute, 90*24*time.Hour, NewMemTokenStore(),
		WithRefreshTokenStore(failStore))
	h := &Handler{
		cfg:      Config{BaseURL: "http://localhost:8080", ExpiresIn: 90 * 24 * time.Hour},
		provider: p,
		store:    store,
	}

	body := "grant_type=refresh_token&refresh_token=test-rt"
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
}

// TestNewHandlerRefreshStoreInitError verifies that NewHandler returns an error
// when the refresh token store path cannot be initialized (e.g., the path
// already exists as a directory rather than a regular file).
func TestNewHandlerRefreshStoreInitError(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	// Pre-create a directory at the .refresh path so NewFileRefreshTokenStore fails.
	refreshPath := storePath + ".refresh"
	if err := os.Mkdir(refreshPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
	})
	_, err := NewHandler(Config{
		BaseURL:        "http://localhost:8080",
		SessionTTL:     10 * time.Minute,
		TokenStorePath: storePath,
	}, p)
	if err == nil {
		t.Fatal("expected error when refresh token store init fails, got nil")
	}
}

// newTestRefreshHandlerWithGitHub creates a Handler wired to a stub GitHub user API
// and configured with extra allowed audiences.
func newTestRefreshHandlerWithGitHub(t *testing.T, extraAudiences []string) (*Handler, *httptest.Server) {
	t.Helper()
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"alice","name":"Alice"}`)
	}))
	t.Cleanup(ghServer.Close)
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		UserAPI:      ghServer.URL + "/user",
		HTTPClient:   ghServer.Client(),
	})
	h, err := NewHandler(Config{
		BaseURL:          "http://localhost:8080",
		SessionTTL:       10 * time.Minute,
		CacheTTL:         5 * time.Minute,
		ExpiresIn:        90 * 24 * time.Hour,
		AllowedAudiences: extraAudiences,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, ghServer
}

// TestTokenRefreshResourceSameAudience verifies that a resource matching the
// original audience is accepted and returns 200.
func TestTokenRefreshResourceSameAudience(t *testing.T) {
	const audience = "http://localhost:8080/mcp/route-a"
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{audience})

	rt, err := h.store.CreateRefreshToken("gha_token", audience, h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape(audience)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["refresh_token"] == nil {
		t.Error("expected rotated refresh_token in response")
	}
}

// TestTokenRefreshResourceNarrowing verifies that a client may narrow a
// gateway-wide audience to a per-route sub-path on refresh.
func TestTokenRefreshResourceNarrowing(t *testing.T) {
	const routeAud = "http://localhost:8080/mcp/route-a"
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{routeAud})

	// Original token is gateway-wide.
	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape(routeAud)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestTokenRefreshResourceCrossRoute verifies that switching from one route
// audience to a sibling route is rejected with 400 invalid_target.
func TestTokenRefreshResourceCrossRoute(t *testing.T) {
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{
		"http://localhost:8080/mcp/route-a",
		"http://localhost:8080/mcp/route-b",
	})

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080/mcp/route-a", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape("http://localhost:8080/mcp/route-b")
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
}

// TestTokenRefreshResourceWidening verifies that broadening a per-route
// audience to gateway-wide is rejected with 400 invalid_target.
func TestTokenRefreshResourceWidening(t *testing.T) {
	const routeAud = "http://localhost:8080/mcp/route-a"
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{routeAud})

	rt, err := h.store.CreateRefreshToken("gha_token", routeAud, h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape("http://localhost:8080")
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
}

// TestTokenRefreshResourceUnknown verifies that an unregistered resource is
// rejected with 400 invalid_target and the refresh token is restored.
func TestTokenRefreshResourceUnknown(t *testing.T) {
	h, _ := newTestRefreshHandlerWithGitHub(t, nil)

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape("https://unknown.example/mcp")
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
	// Token must be restored so the client can retry with a valid resource.
	if _, err := h.store.UseRefreshToken(rt); err != nil {
		t.Error("refresh token should be restored after invalid resource rejection")
	}
}

// TestTokenRefreshResourceLegacyToken verifies that a legacy token (empty
// stored audience) accepts any registered resource as a valid narrowing.
func TestTokenRefreshResourceLegacyToken(t *testing.T) {
	const routeAud = "http://localhost:8080/mcp/route-a"
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{routeAud})

	// Empty audience simulates a pre-audience (legacy) refresh token.
	rt, err := h.store.CreateRefreshToken("gha_token", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=" + url.QueryEscape(routeAud)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestTokenRefreshResourceEmptyValue verifies that resource= (empty value) is
// rejected as invalid_target (RFC 8707 requires a non-empty absolute URI).
func TestTokenRefreshResourceEmptyValue(t *testing.T) {
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{"http://localhost:8080/mcp/route-a"})

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource="
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
}

// TestTokenRefreshResourceMultipleRaw verifies that resource=&resource=https://x
// (one empty, one valid) is rejected — raw count check ignores empty filtering.
func TestTokenRefreshResourceMultipleRaw(t *testing.T) {
	const routeAud = "http://localhost:8080/mcp/route-a"
	h, _ := newTestRefreshHandlerWithGitHub(t, []string{routeAud})

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	// resource= (empty) is present first — should be rejected before multi-check
	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=&resource=" + url.QueryEscape(routeAud)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]string
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
}
