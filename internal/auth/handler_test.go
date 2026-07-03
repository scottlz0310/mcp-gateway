package auth

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
)

func newTestHandler(t *testing.T, opts ...HandlerOption) *Handler {
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
	}, p, opts...)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func newAuditRecorder(t *testing.T) (*authaudit.FileRecorder, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	recorder, err := authaudit.New(authaudit.Config{
		Path:            path,
		MaxSizeBytes:    1 << 20,
		MaxBackups:      2,
		MaxAge:          24 * time.Hour,
		FailureCapacity: authaudit.DefaultFailureLimit,
	})
	if err != nil {
		t.Fatalf("authaudit.New: %v", err)
	}
	return recorder, path
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

	register := func() map[string]any {
		r := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.Register(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("status: got %d, want %d", w.Code, http.StatusCreated)
		}
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
		return resp
	}

	resp1 := register()
	resp2 := register()

	id1, _ := resp1["client_id"].(string)
	id2, _ := resp2["client_id"].(string)

	if id1 == "" {
		t.Error("client_id must not be empty")
	}
	if id1 == id2 {
		t.Errorf("client_id must be unique per registration, got same value %q twice", id1)
	}
	if resp1["token_endpoint_auth_method"] != "none" {
		t.Errorf("token_endpoint_auth_method: got %v", resp1["token_endpoint_auth_method"])
	}
}

// TestDCRClientIDPropagatesToIDTokenAud verifies that the client_id issued via
// DCR (/register) is forwarded as the aud claim in the id_token issued at
// /token.  Before this fix, aud was always h.provider.ClientID() regardless of
// the registering client's identity.
func TestDCRClientIDPropagatesToIDTokenAud(t *testing.T) {
	h := newTestHandler(t)

	// Simulate a DCR client registering and then going through /authorize.
	// SaveSession is called by Authorize() with client_id from the query param;
	// here we bypass the HTTP layer to control inputs directly.
	const dcrClientID = "dcr-client-unique-abc123"
	h.store.SaveSession("dcr-state", "http://localhost/cb", "", "http://localhost:8080", "", dcrClientID)
	code, err := h.store.CompleteCallback("dcr-state", "provider-tok", "openid", "", time.Time{}, "alice")
	if err != nil {
		t.Fatalf("CompleteCallback: %v", err)
	}

	body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost/cb", code)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("token: got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}
	idToken, ok := resp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("expected id_token in response when openid scope requested")
	}

	claims := parseJWTPayload(t, idToken)
	if got := claims["aud"]; got != dcrClientID {
		t.Errorf("id_token.aud: got %v, want %q (DCR-issued client_id)", got, dcrClientID)
	}
}

// TestIDTokenAudFallsBackToProviderClientID verifies that when no client_id is
// stored in the session (legacy or non-DCR flow), id_token.aud falls back to
// h.provider.ClientID().
func TestIDTokenAudFallsBackToProviderClientID(t *testing.T) {
	h := newTestHandler(t)

	h.store.SaveSession("legacy-state", "http://localhost/cb", "", "http://localhost:8080", "", "")
	code, err := h.store.CompleteCallback("legacy-state", "provider-tok", "openid", "", time.Time{}, "bob")
	if err != nil {
		t.Fatalf("CompleteCallback: %v", err)
	}

	body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost/cb", code)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("token: got %d; body: %s", w.Code, w.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}
	idToken, ok := resp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("expected id_token in response when openid scope requested")
	}

	claims := parseJWTPayload(t, idToken)
	if got := claims["aud"]; got != "test-client-id" {
		t.Errorf("id_token.aud: got %v, want %q (provider ClientID fallback)", got, "test-client-id")
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

func TestAuthorizeDefaultAllowedRedirectHosts(t *testing.T) {
	h := newTestHandler(t)
	// antigravity.google should be allowed by default
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=https://antigravity.google/cb", nil)
	w := httptest.NewRecorder()

	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Errorf("antigravity.google should be allowed by default: got %d, want %d", w.Code, http.StatusFound)
	}
}

func TestAuthorizeCustomAllowedRedirectHosts(t *testing.T) {
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://gateway.example.com:8080/callback",
		Scopes:       "repo,user",
	})
	// Use a non-localhost BaseURL to avoid it being automatically added to the default list.
	h, err := NewHandler(Config{
		BaseURL:              "http://gateway.example.com:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		AllowedRedirectHosts: []string{"custom-allowed.com"},
	}, p)
	if err != nil {
		t.Fatalf("failed to create handler: %v", err)
	}

	// custom-allowed.com should be allowed (explicitly configured)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=https://custom-allowed.com/cb", nil)
	w := httptest.NewRecorder()
	h.Authorize(w, r)
	if w.Code != http.StatusFound {
		t.Errorf("custom-allowed.com should be allowed: got %d, want %d", w.Code, http.StatusFound)
	}

	// gateway.example.com is the BaseURL host — automatically added so /device_callback works.
	r3 := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=http://gateway.example.com:8080/device_callback", nil)
	w3 := httptest.NewRecorder()
	h.Authorize(w3, r3)
	if w3.Code != http.StatusFound {
		t.Errorf("BaseURL host should be auto-allowed: got %d, want %d", w3.Code, http.StatusFound)
	}

	// localhost should be disallowed since it was overridden (not in AllowedRedirectHosts, not BaseURL host)
	r2 := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=https://localhost/cb", nil)
	w2 := httptest.NewRecorder()
	h.Authorize(w2, r2)
	if w2.Code != http.StatusBadRequest {
		t.Errorf("localhost should be disallowed when overridden: got %d, want %d", w2.Code, http.StatusBadRequest)
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

func TestOAuthAuditEventsAndSecretRedaction(t *testing.T) {
	recorder, auditPath := newAuditRecorder(t)
	p := &provider.Mock{
		NameValue:     "github",
		ClientIDValue: "test-client-id",
		ScopesValue:   "repo,user",
		ExchangeCodeFunc: func(_ context.Context, code string) (provider.TokenResponse, error) {
			if code != "provider-secret-code" {
				return provider.TokenResponse{}, fmt.Errorf("unexpected authorization code")
			}
			return provider.TokenResponse{
				AccessToken:          "secret-access-token",
				RefreshToken:         "secret-provider-refresh-token",
				AccessTokenExpiresIn: 30 * time.Second,
				Scopes:               []string{"repo", "user"},
			}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "github", Subject: "alice"}, nil
		},
		RefreshTokenFunc: func(_ context.Context, refreshToken string) (provider.TokenResponse, error) {
			if refreshToken != "secret-provider-refresh-token" {
				return provider.TokenResponse{}, fmt.Errorf("unexpected provider refresh token")
			}
			return provider.TokenResponse{
				AccessToken:          "rotated-secret-access-token",
				RefreshToken:         "rotated-secret-provider-refresh-token",
				AccessTokenExpiresIn: time.Hour,
			}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		GitHubRefreshEnabled: true,
	}, p, WithAuditRecorder(recorder))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=secret-state&redirect_uri=http://localhost/cb", nil)
	authRec := httptest.NewRecorder()
	h.Authorize(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize status: got %d", authRec.Code)
	}

	callbackReq := httptest.NewRequest(http.MethodGet,
		"/callback?code=provider-secret-code&state=secret-state", nil)
	callbackRec := httptest.NewRecorder()
	h.Callback(callbackRec, callbackReq)
	if callbackRec.Code != http.StatusFound {
		t.Fatalf("callback status: got %d; body=%s", callbackRec.Code, callbackRec.Body.String())
	}
	redirectURL, err := url.Parse(callbackRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	internalCode := redirectURL.Query().Get("code")
	if internalCode == "" {
		t.Fatal("callback redirect missing internal code")
	}

	tokenBody := "grant_type=authorization_code&redirect_uri=http%3A%2F%2Flocalhost%2Fcb&code=" + url.QueryEscape(internalCode)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token status: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	var tokenResponse map[string]any
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResponse); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	gatewayRefreshToken, _ := tokenResponse["refresh_token"].(string)
	if gatewayRefreshToken == "" {
		t.Fatal("token response missing gateway refresh token")
	}

	if _, rotated, err := h.ValidateToken(context.Background(), "secret-access-token", "mcp-gateway"); err != nil {
		t.Fatalf("ValidateToken: %v", err)
	} else if rotated != "rotated-secret-access-token" {
		t.Fatalf("rotated token: got %q", rotated)
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(gatewayRefreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh status: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}

	deniedReq := httptest.NewRequest(http.MethodGet,
		"/callback?error=access_denied&error_description=contains-secret&state=another-secret-state", nil)
	deniedRec := httptest.NewRecorder()
	h.Callback(deniedRec, deniedReq)
	if deniedRec.Code != http.StatusBadRequest {
		t.Fatalf("denied callback status: got %d", deniedRec.Code)
	}

	if err := recorder.Close(); err != nil {
		t.Fatalf("recorder.Close: %v", err)
	}
	data, err := os.ReadFile(auditPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var phases = map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event authaudit.Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid audit JSON line: %v", err)
		}
		if event.Result == "success" {
			phases[event.Phase] = true
		}
	}
	for _, phase := range []string{"authorize", "callback", "token_exchange", "identity_resolution", "refresh", "rotation"} {
		if !phases[phase] {
			t.Errorf("missing successful audit phase %q", phase)
		}
	}
	failures := recorder.RecentFailures()
	if len(failures) != 1 || failures[0].OAuthError != "access_denied" {
		t.Fatalf("recent failures: got %#v", failures)
	}
	for _, secret := range []string{
		"secret-state",
		"another-secret-state",
		"provider-secret-code",
		"secret-access-token",
		"secret-provider-refresh-token",
		"rotated-secret-access-token",
		"contains-secret",
		gatewayRefreshToken,
	} {
		if strings.Contains(string(data), secret) {
			t.Errorf("audit log contains secret value %q", secret)
		}
	}
}

func TestAuthorizeResourceAudienceStoredOnToken(t *testing.T) {
	const routeAudience = "mcp-server"
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ScopesValue:   "repo,user",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{
				AccessToken: "opaque-route-token",
				Scopes:      []string{"repo", "user"},
			}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:             "http://localhost:8080",
		SessionTTL:          10 * time.Minute,
		CacheTTL:            5 * time.Minute,
		ExpiresIn:           90 * 24 * time.Hour,
		ResourceAudienceMap: map[string]string{"foo": routeAudience},
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=state-aud&redirect_uri=http://localhost/cb&resource=foo", nil)
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
	subject, rotated, err := h.ValidateToken(context.Background(), "opaque-route-token", routeAudience)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if subject != "alice" {
		t.Errorf("subject: got %q, want alice", subject)
	}
	if rotated != "" {
		t.Errorf("rotated token: got %q, want empty", rotated)
	}
}

func TestAuthorizeRejectsUnknownResource(t *testing.T) {
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=s&redirect_uri=http://localhost/cb&resource=missing-route", nil)
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

	_, _, err := h.ValidateToken(context.Background(), "route-token", "http://localhost:8080/mcp/b")
	if !errors.Is(err, ErrTokenAudienceMismatch) {
		t.Fatalf("ValidateToken err: got %v, want ErrTokenAudienceMismatch", err)
	}
}

// TestValidateTokenReseedsSubjectIndexOnCacheHit simulates a gateway restart
// where the persistent token store still has cached records but the in-memory
// subject index has been lost. The first ValidateToken cache hit must
// re-seed the subject index so that the Phase B delegated-access API
// (LatestBySubject) can resolve the subject immediately.
func TestValidateTokenReseedsSubjectIndexOnCacheHit(t *testing.T) {
	h := newTestHandler(t)
	const subject = "github|reseed-user"
	const tok = "reseed-token"
	h.store.CacheToken(tok, subject, "")

	// Drop the in-memory subject index to simulate a process restart with a
	// persistent token store that has rehydrated records but no live index.
	h.store.subjectIndexMu.Lock()
	delete(h.store.subjectIndex, subject)
	h.store.subjectIndexMu.Unlock()

	if _, _, ok := h.store.LatestBySubject(subject); ok {
		t.Fatalf("precondition: LatestBySubject should be empty after index clear")
	}

	got, rotated, err := h.ValidateToken(context.Background(), tok, "")
	if err != nil {
		t.Fatalf("ValidateToken err: %v", err)
	}
	if got != subject {
		t.Errorf("ValidateToken subject: got %q, want %q", got, subject)
	}
	if rotated != "" {
		t.Errorf("ValidateToken rotated: got %q, want empty", rotated)
	}

	rawToken, rec, ok := h.store.LatestBySubject(subject)
	if !ok {
		t.Fatalf("LatestBySubject ok: got false, want true (cache-hit must re-seed)")
	}
	if rawToken != tok {
		t.Errorf("LatestBySubject token: got %q, want %q", rawToken, tok)
	}
	if rec.Subject != subject {
		t.Errorf("LatestBySubject subject: got %q, want %q", rec.Subject, subject)
	}
}

// TestValidateTokenAudiencePrefixMatching covers the gateway-wide ↁEroute-scoped
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
		{
			// trailing-slash recorded values must be normalized before
			// isSubAudience comparison, otherwise "http://gw/" + "/" = "http://gw//"
			// which would never match descendants.
			name:      "recorded_with_trailing_slash_accepts_descendant",
			recorded:  "http://localhost:8080/",
			requested: "http://localhost:8080/mcp/github",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t)
			h.store.RegisterTokenAudience("token", tc.recorded)
			h.store.CacheToken("token", "alice", "")

			subject, _, err := h.ValidateToken(context.Background(), "token", tc.requested)
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

// TestValidateAudienceSkipsEmptyRecorded ensures that a stale or malformed
// TokenRecord containing empty-string audience entries cannot bypass strict
// mode. Empty entries are skipped by validateAudience so isSubAudience's
// wildcard-on-empty semantics (used by the refresh-token grace path) cannot
// leak into per-request validation.
func TestValidateAudienceSkipsEmptyRecorded(t *testing.T) {
	h, err := NewHandler(Config{
		BaseURL:             "http://localhost:8080",
		SessionTTL:          10 * time.Minute,
		CacheTTL:            5 * time.Minute,
		TokenAudienceStrict: true,
	}, &provider.Mock{ClientIDValue: "test-client-id"})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	record := TokenRecord{Audiences: []string{""}}
	got := h.validateAudience("token", record, "http://localhost:8080/mcp/github")
	if !errors.Is(got, ErrTokenAudienceMismatch) {
		t.Fatalf("got %v, want ErrTokenAudienceMismatch", got)
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
	subject, _, err := grace.ValidateToken(context.Background(), "legacy-token", audience)
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
	_, _, err = strict.ValidateToken(context.Background(), "legacy-token", audience)
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
	h := newTestHandler(t)

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
	userCode, _ := resp["user_code"].(string)
	if userCode == "" {
		t.Error("user_code must be non-empty")
	}
	if len(userCode) != 9 || userCode[4] != '-' {
		t.Errorf("user_code must be XXXX-XXXX format, got %q", userCode)
	}
	if resp["verification_uri"] != "http://localhost:8080/activate" {
		t.Errorf("verification_uri: got %v", resp["verification_uri"])
	}
	wantComplete := "http://localhost:8080/activate?user_code=" + userCode
	if resp["verification_uri_complete"] != wantComplete {
		t.Errorf("verification_uri_complete: got %v, want %v", resp["verification_uri_complete"], wantComplete)
	}
	if resp["device_code"] == nil || resp["device_code"] == "" {
		t.Error("device_code must be non-empty")
	}
	if resp["interval"] != float64(5) {
		t.Errorf("interval: got %v, want 5", resp["interval"])
	}
}

func TestDeviceAuthorizeMalformedBodyAudited(t *testing.T) {
	recorder, _ := newAuditRecorder(t)
	defer func() { _ = recorder.Close() }()
	h := newTestHandler(t, WithAuditRecorder(recorder))
	r := httptest.NewRequest(http.MethodPost, "/device_authorization",
		strings.NewReader(strings.Repeat("x", (64<<10)+1)))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.DeviceAuthorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400; body: %s", w.Code, w.Body.String())
	}
	failures := recorder.RecentFailures()
	if len(failures) != 1 {
		t.Fatalf("failure count: got %d, want 1", len(failures))
	}
	if got := failures[0]; got.Phase != "authorize" ||
		got.ErrorClass != "invalid_request" ||
		got.Message != "device authorization request body rejected" {
		t.Fatalf("audit failure: got %#v", got)
	}
}

func TestActivateFormRendered(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/activate", nil)
	w := httptest.NewRecorder()
	h.Activate(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "user_code") {
		t.Error("activate form should contain user_code input")
	}
}

func TestActivateFormPrefill(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/activate?user_code=ABCD-1234", nil)
	w := httptest.NewRecorder()
	h.Activate(w, r)

	if !strings.Contains(w.Body.String(), "ABCD-1234") {
		t.Error("activate form should prefill user_code from query parameter")
	}
}

func TestActivateSubmitInvalidCode(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodPost, "/activate",
		strings.NewReader("user_code=XXXX-9999"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ActivateSubmit(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestActivateSubmitValidCode(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("ABCD-5678", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	r := httptest.NewRequest(http.MethodPost, "/activate",
		strings.NewReader("user_code=ABCD-5678"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ActivateSubmit(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want 302; body: %s", w.Code, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "/authorize") {
		t.Errorf("should redirect to /authorize, got %q", loc)
	}
	wantState := url.QueryEscape("device:" + internalCode)
	if !strings.Contains(loc, "state="+wantState) {
		t.Errorf("state should encode device code, got %q", loc)
	}
}

func TestDeviceCallbackInvalidState(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/device_callback?code=abc&state=invalid-state", nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestDeviceCallbackMissingParams(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodGet, "/device_callback", nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestTokenDeviceGrantPending(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("WDJB-MJHT", expiresAt, "mcp-gateway", "")
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

func TestTokenDeviceGrantSlowDown(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("ABCD-1234", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("creating device session: %v", err)
	}

	poll := func() map[string]any {
		body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
		r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		h.Token(w, r)
		var resp map[string]any
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("decoding response: %v", err)
		}
		return resp
	}

	// First poll: no interval yet → authorization_pending.
	first := poll()
	if first["error"] != "authorization_pending" {
		t.Errorf("first poll: want authorization_pending, got %v", first["error"])
	}
	// Second poll immediately: interval not elapsed → slow_down.
	second := poll()
	if second["error"] != "slow_down" {
		t.Errorf("second poll (too fast): want slow_down, got %v", second["error"])
	}
}

func TestTokenDeviceGrantSuccess(t *testing.T) {
	ghServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"login":"octocat","name":"The Octocat"}`)
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

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("WDJB-MJHT", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("creating device session: %v", err)
	}

	// Simulate /device_callback approving the device.
	if !h.store.ApproveDevice(internalCode, "gha_success_token", "repo,user", "octocat", "", time.Time{}) {
		t.Fatal("ApproveDevice failed")
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
	rt, err := h.store.CreateRefreshToken("gha_existing_token", "http://localhost:8080/mcp", "", h.refreshTokenTTL())
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

	rt, err := h.store.CreateRefreshToken("gha_token", "http://localhost:8080/mcp", "", h.refreshTokenTTL())
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

	rt, err := h.store.CreateRefreshToken("gha_concurrent_token", "http://localhost:8080/mcp", "", h.refreshTokenTTL())
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
	rt, err := h1.store.CreateRefreshToken("gha_access_token", "http://localhost:8080/mcp", "", 24*time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	// Close h1 before reopening the same SQLite file.
	if err := h1.Close(); err != nil {
		t.Fatalf("h1.Close: %v", err)
	}

	// Re-instantiate handler (simulating restart) with the same store path.
	h2 := newHandlerWithPath(t, storePath)
	t.Cleanup(func() { _ = h2.Close() })
	accessToken, err := h2.store.PeekRefreshToken(rt)
	if err != nil {
		t.Fatalf("PeekRefreshToken after restart: %v", err)
	}
	if accessToken != "gha_access_token" {
		t.Errorf("access token after restart: got %q, want %q", accessToken, "gha_access_token")
	}

	// Verify the .refresh.db sibling file was created alongside the configured path.
	refreshPath := storePath + ".refresh.db"
	if _, statErr := os.Stat(refreshPath); statErr != nil {
		t.Errorf(".refresh.db sibling file not created: %v", statErr)
	}
}

// TestNewHandlerMigratesLegacyTokenStore verifies that a legacy tokens.json
// written by the file-backed TokenStore is imported into the SQLite store on
// startup and renamed to .migrated, so tokens validated before the upgrade
// keep working (#191).
func TestNewHandlerMigratesLegacyTokenStore(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")

	legacy, err := NewFileTokenStore(storePath)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	if err := legacy.Save("tok-legacy", "alice", []string{"http://localhost:8080/mcp"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("legacy Save: %v", err)
	}

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
		TokenStorePath: storePath,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	rec, ok := h.store.tokens.Lookup("tok-legacy")
	if !ok {
		t.Fatal("legacy token not found in SQLite store after migration")
	}
	if rec.Subject != "alice" {
		t.Errorf("Subject: got %q, want %q", rec.Subject, "alice")
	}
	if _, statErr := os.Stat(storePath); !os.IsNotExist(statErr) {
		t.Error("legacy tokens.json should have been renamed after migration")
	}
	if _, statErr := os.Stat(storePath + ".migrated"); statErr != nil {
		t.Errorf("tokens.json.migrated not found: %v", statErr)
	}
}

// ── error-injection helpers ───────────────────────────────────────────────────

// deleteFailRefreshStore wraps a real in-memory store for all operations
// except Delete, which always returns an error.  This causes
// ReserveRefreshToken to return ErrRefreshTokenDeleteFailed.
type deleteFailRefreshStore struct {
	inner *memRefreshTokenStore
}

func (d *deleteFailRefreshStore) Save(rt, at, aud, fid string, exp time.Time) error {
	return d.inner.Save(rt, at, aud, fid, exp)
}
func (d *deleteFailRefreshStore) Lookup(rt string) (string, string, string, time.Time, bool) {
	return d.inner.Lookup(rt)
}
func (d *deleteFailRefreshStore) LookupAny(rt string) (string, string, string, time.Time, bool, bool) {
	return d.inner.LookupAny(rt)
}
func (d *deleteFailRefreshStore) Revoke(_ string) error { return fmt.Errorf("disk I/O error") }
func (d *deleteFailRefreshStore) RevokeFamily(fid string) (string, error) {
	return d.inner.RevokeFamily(fid)
}
func (d *deleteFailRefreshStore) SaveNonce(rt, n string) error { return d.inner.SaveNonce(rt, n) }
func (d *deleteFailRefreshStore) LookupNonce(rt string) string { return d.inner.LookupNonce(rt) }
func (d *deleteFailRefreshStore) SaveProviderAccessToken(rt, pat string) error {
	return d.inner.SaveProviderAccessToken(rt, pat)
}
func (d *deleteFailRefreshStore) LookupProviderAccessToken(rt string) string {
	return d.inner.LookupProviderAccessToken(rt)
}
func (d *deleteFailRefreshStore) SaveProviderRefresh(rt, prt string, exp time.Time) error {
	return d.inner.SaveProviderRefresh(rt, prt, exp)
}
func (d *deleteFailRefreshStore) LookupProviderRefresh(rt string) (string, time.Time) {
	return d.inner.LookupProviderRefresh(rt)
}
func (d *deleteFailRefreshStore) UpdateProviderTokensByAccessToken(at, pat, prt string, exp time.Time) error {
	return d.inner.UpdateProviderTokensByAccessToken(at, pat, prt, exp)
}
func (d *deleteFailRefreshStore) RevokeJTI(jti string, exp time.Time) error {
	return d.inner.RevokeJTI(jti, exp)
}
func (d *deleteFailRefreshStore) IsJTIRevoked(jti string) bool { return d.inner.IsJTIRevoked(jti) }
func (d *deleteFailRefreshStore) Delete(_ string) error        { return fmt.Errorf("disk I/O error") }
func (d *deleteFailRefreshStore) Sweep() error                 { return d.inner.Sweep() }

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

	inner := &memRefreshTokenStore{
		entries:                  make(map[string]memRTEntry),
		revokedJTI:               make(map[string]time.Time),
		revokedFamilies:          make(map[string]struct{}),
		familyCurrentAccessToken: make(map[string]memFamilyPointer),
	}
	failStore := &deleteFailRefreshStore{inner: inner}
	_ = inner.Save("test-rt", "test-at", "http://localhost:8080/mcp", "fid-test", time.Now().Add(time.Hour))

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
	// Pre-create a directory at the .refresh.db path so NewSQLiteRefreshTokenStore fails.
	refreshPath := storePath + ".refresh.db"
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

// TestNewHandlerClosesDBOnTokenMigrationFailure verifies that when
// migrateFileTokenStore fails, NewHandler closes the shared SQLite handle
// before returning rather than leaking it (thread-owl review, PR #196):
// leaving the handle open would keep the underlying .refresh.db file locked,
// which on Windows makes even removing the file fail with "the process
// cannot access the file because it is being used by another process".
func TestNewHandlerClosesDBOnTokenMigrationFailure(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(storePath, []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("writing corrupt tokens.json: %v", err)
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
		t.Fatal("expected error from corrupt legacy tokens.json, got nil")
	}

	refreshDBPath := storePath + ".refresh.db"
	if _, statErr := os.Stat(refreshDBPath); statErr != nil {
		t.Fatalf(".refresh.db should have been created before migration ran: %v", statErr)
	}
	if removeErr := os.Remove(refreshDBPath); removeErr != nil {
		t.Errorf("removing .refresh.db after failed migration: %v (handle appears to be leaked)", removeErr)
	}
}

// TestNewHandlerClosesDBOnRefreshMigrationFailure is the counterpart of
// TestNewHandlerClosesDBOnTokenMigrationFailure for the second migration call
// (migrateFileRefreshTokenStore) in the same NewHandler error path.
func TestNewHandlerClosesDBOnRefreshMigrationFailure(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(storePath+".refresh", []byte("{not valid json"), 0o600); err != nil {
		t.Fatalf("writing corrupt tokens.json.refresh: %v", err)
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
		t.Fatal("expected error from corrupt legacy tokens.json.refresh, got nil")
	}

	refreshDBPath := storePath + ".refresh.db"
	if _, statErr := os.Stat(refreshDBPath); statErr != nil {
		t.Fatalf(".refresh.db should have been created before migration ran: %v", statErr)
	}
	if removeErr := os.Remove(refreshDBPath); removeErr != nil {
		t.Errorf("removing .refresh.db after failed migration: %v (handle appears to be leaked)", removeErr)
	}
}

// newTestRefreshHandlerWithGitHub creates a Handler wired to a stub GitHub user API
// and configured with a ResourceAudienceMap for refresh token audience tests.
func newTestRefreshHandlerWithGitHub(t *testing.T, resourceMap map[string]string) (*Handler, *httptest.Server) {
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
		BaseURL:             "http://localhost:8080",
		SessionTTL:          10 * time.Minute,
		CacheTTL:            5 * time.Minute,
		ExpiresIn:           90 * 24 * time.Hour,
		ResourceAudienceMap: resourceMap,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h, ghServer
}

// TestTokenRefreshResourceSameAudience verifies that a resource matching the
// original audience is accepted and returns 200.
func TestTokenRefreshResourceSameAudience(t *testing.T) {
	const audience = "mcp-server"
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": audience})

	rt, err := h.store.CreateRefreshToken("gha_token", audience, "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=route-a"
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
// gateway-wide audience to a per-route audience on refresh.
func TestTokenRefreshResourceNarrowing(t *testing.T) {
	const routeAud = "mcp-server"
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": routeAud})

	// Original token is gateway-wide (mcp-gateway).
	rt, err := h.store.CreateRefreshToken("gha_token", "mcp-gateway", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=route-a"
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestTokenRefreshResourceCrossRoute verifies that switching from one route
// audience to a distinct sibling audience is rejected with 400 invalid_target.
func TestTokenRefreshResourceCrossRoute(t *testing.T) {
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{
		"route-a": "mcp-server",
		"route-b": "external-mcp",
	})

	rt, err := h.store.CreateRefreshToken("gha_token", "mcp-server", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=route-b"
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
// audience to the gateway-wide audience is rejected with 400 invalid_target.
func TestTokenRefreshResourceWidening(t *testing.T) {
	const routeAud = "mcp-server"
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": routeAud})

	rt, err := h.store.CreateRefreshToken("gha_token", routeAud, "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=mcp-gateway"
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

	rt, err := h.store.CreateRefreshToken("gha_token", "mcp-gateway", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=unknown-route"
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
	const routeAud = "mcp-server"
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": routeAud})

	// Empty audience simulates a pre-audience (legacy) refresh token.
	rt, err := h.store.CreateRefreshToken("gha_token", "", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=route-a"
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d, want 200; body: %s", w.Code, w.Body.String())
	}
}

// TestTokenRefreshResourceEmptyValue verifies that resource= (empty value) is
// rejected as invalid_target.
func TestTokenRefreshResourceEmptyValue(t *testing.T) {
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": "mcp-server"})

	rt, err := h.store.CreateRefreshToken("gha_token", "mcp-gateway", "", h.refreshTokenTTL())
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

// TestTokenRefreshResourceMultipleRaw verifies that resource=&resource=route-a
// (one empty, one valid) is rejected — empty value check runs before multi-check.
func TestTokenRefreshResourceMultipleRaw(t *testing.T) {
	const routeAud = "mcp-server"
	h, _ := newTestRefreshHandlerWithGitHub(t, map[string]string{"route-a": routeAud})

	rt, err := h.store.CreateRefreshToken("gha_token", "mcp-gateway", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("seeding refresh token: %v", err)
	}

	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt) + "&resource=&resource=route-a"
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

// TestValidateTokenGitHubRotation exercises Phase A rotation: when the cached
// provider access expiry is within the configured leeway window, ValidateToken
// must call Provider.RefreshToken, cache the new access token under its own
// key, keep the original entry cached (with refreshed provider metadata so a
// subsequent in-window request from the same client triggers rotation again),
// and surface the rotated token to callers via the second return value.
// Parameterised on rotation outcome.
func TestValidateTokenGitHubRotation(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	cases := []struct {
		name             string
		gateEnabled      bool
		providerExpiryIn time.Duration // relative to now; zero means "no expiry hint"
		providerRefresh  string        // empty means no metadata cached
		refreshFunc      func(ctx context.Context, rt string) (provider.TokenResponse, error)
		wantRotated      string
		wantSubject      string
		wantRefreshCalls int
	}{
		{
			name:             "happy path within leeway window",
			gateEnabled:      true,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "rt-old",
			refreshFunc: func(_ context.Context, rt string) (provider.TokenResponse, error) {
				if rt != "rt-old" {
					return provider.TokenResponse{}, fmt.Errorf("unexpected refresh token %q", rt)
				}
				return provider.TokenResponse{
					AccessToken:          "new-access",
					RefreshToken:         "rt-new",
					AccessTokenExpiresIn: 28800 * time.Second,
				}, nil
			},
			wantRotated:      "new-access",
			wantSubject:      "alice",
			wantRefreshCalls: 1,
		},
		{
			name:             "just inside the leeway boundary",
			gateEnabled:      true,
			providerExpiryIn: defaultGitHubRefreshLeeway - 1*time.Second,
			providerRefresh:  "rt-old",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{
					AccessToken:          "edge-new",
					AccessTokenExpiresIn: 28800 * time.Second,
				}, nil
			},
			wantRotated:      "edge-new",
			wantSubject:      "alice",
			wantRefreshCalls: 1,
		},
		{
			name:             "outside leeway: rotation skipped",
			gateEnabled:      true,
			providerExpiryIn: 1 * time.Hour,
			providerRefresh:  "rt-old",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, fmt.Errorf("refresh must not be called when expiry is outside leeway")
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 0,
		},
		{
			name:             "provider refresh failure falls back to cached subject",
			gateEnabled:      true,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "rt-bad",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, fmt.Errorf("bad_refresh_token")
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 1,
		},
		{
			name:             "gate disabled: rotation skipped even when ripe",
			gateEnabled:      false,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "rt-old",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, fmt.Errorf("refresh must not be called when gate is disabled")
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 0,
		},
		{
			name:             "no provider metadata cached: rotation skipped",
			gateEnabled:      true,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, fmt.Errorf("refresh must not be called without cached refresh token")
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 0,
		},
		{
			name:             "provider returns empty access token: rotation aborted",
			gateEnabled:      true,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "rt-empty",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{AccessToken: ""}, nil
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 1,
		},
		{
			name:             "provider returns ErrRefreshNotSupported: treated as inert",
			gateEnabled:      true,
			providerExpiryIn: 30 * time.Second,
			providerRefresh:  "rt-old",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, provider.ErrRefreshNotSupported
			},
			wantRotated:      "",
			wantSubject:      "alice",
			wantRefreshCalls: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var refreshCalls int
			p := &provider.Mock{
				ClientIDValue: "test-client-id",
				ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
					return provider.Identity{Provider: "mock", Subject: "alice"}, nil
				},
				RefreshTokenFunc: func(ctx context.Context, rt string) (provider.TokenResponse, error) {
					refreshCalls++
					return tc.refreshFunc(ctx, rt)
				},
			}
			h, err := NewHandler(Config{
				BaseURL:              "http://localhost:8080",
				SessionTTL:           10 * time.Minute,
				CacheTTL:             5 * time.Minute,
				ExpiresIn:            90 * 24 * time.Hour,
				AllowedAudiences:     []string{audience},
				GitHubRefreshEnabled: tc.gateEnabled,
			}, p)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			h.store.CacheToken("old-access", "alice", audience)
			if tc.providerRefresh != "" {
				var expiry time.Time
				if tc.providerExpiryIn > 0 {
					expiry = time.Now().Add(tc.providerExpiryIn)
				}
				h.store.RecordProviderRefresh("old-access", tc.providerRefresh, expiry)
			}

			subject, rotated, err := h.ValidateToken(context.Background(), "old-access", audience)
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if subject != tc.wantSubject {
				t.Errorf("subject: got %q, want %q", subject, tc.wantSubject)
			}
			if rotated != tc.wantRotated {
				t.Errorf("rotated: got %q, want %q", rotated, tc.wantRotated)
			}
			if refreshCalls != tc.wantRefreshCalls {
				t.Errorf("refresh calls: got %d, want %d", refreshCalls, tc.wantRefreshCalls)
			}
			if tc.wantRotated != "" {
				rec, ok := h.store.LookupToken(tc.wantRotated)
				if !ok {
					t.Fatal("expected new access token to be cached after rotation")
				}
				if rec.Subject != tc.wantSubject {
					t.Errorf("new cache subject: got %q, want %q", rec.Subject, tc.wantSubject)
				}
				// Old entry must remain cached: clients keep presenting it and
				// dropping it would force a provider round-trip  Epossibly a
				// 401 once GitHub expires the original.
				oldRec, oldCached := h.store.LookupToken("old-access")
				if !oldCached {
					t.Fatal("old access token must remain cached after rotation so the client can keep using it")
				}
				if oldRec.ProviderRefreshToken == "" {
					t.Error("old entry must carry refreshed provider metadata for the next rotation cycle")
				}
			}
		})
	}
}

// TestPersistProviderRefreshGate verifies that GitHub refresh-token metadata
// is written to the token store only when GitHubRefreshEnabled is true.  When
// the gate is off, neither tokenAuthCode nor tokenDeviceGrant must leak the
// refresh_token onto disk; this is the security guarantee documented in
// configuration.md.
func TestPersistProviderRefreshGate(t *testing.T) {
	cases := []struct {
		name        string
		gateEnabled bool
		wantStored  bool
	}{
		{name: "flag on persists provider refresh metadata", gateEnabled: true, wantStored: true},
		{name: "flag off skips persistence entirely", gateEnabled: false, wantStored: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &provider.Mock{ClientIDValue: "test-client-id"}
			h, err := NewHandler(Config{
				BaseURL:              "http://localhost:8080",
				SessionTTL:           10 * time.Minute,
				CacheTTL:             5 * time.Minute,
				ExpiresIn:            90 * 24 * time.Hour,
				GitHubRefreshEnabled: tc.gateEnabled,
			}, p)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			h.store.RegisterTokenAudience("gha_token", "http://localhost:8080")
			h.persistProviderRefresh("gha_token", "ghrt-secret", time.Now().Add(time.Hour))

			rec, ok := h.store.LookupToken("gha_token")
			if !ok {
				t.Fatal("token entry should exist after RegisterTokenAudience")
			}
			if tc.wantStored && rec.ProviderRefreshToken != "ghrt-secret" {
				t.Errorf("provider refresh token: got %q, want %q", rec.ProviderRefreshToken, "ghrt-secret")
			}
			if !tc.wantStored && rec.ProviderRefreshToken != "" {
				t.Errorf("provider refresh token must not be stored when gate is off, got %q", rec.ProviderRefreshToken)
			}
		})
	}
}

// TestValidateTokenGitHubRotationSingleflight verifies that concurrent
// ValidateToken calls for the same bearer token collapse into a single
// provider.RefreshToken invocation, with all callers receiving the same
// rotated access token.  Without singleflight, a burst of in-window requests
// would race to refresh and GitHub would reject the second call as
// bad_refresh_token.
func TestValidateTokenGitHubRotationSingleflight(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	const concurrency = 8

	var (
		refreshCalls int32
		releaseCh    = make(chan struct{})
	)
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			atomic.AddInt32(&refreshCalls, 1)
			// Hold the leader inside the provider call so that followers
			// definitely arrive while the singleflight key is still in flight.
			<-releaseCh
			return provider.TokenResponse{
				AccessToken:          "rotated-once",
				RefreshToken:         "rt-new",
				AccessTokenExpiresIn: 28800 * time.Second,
			}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		AllowedAudiences:     []string{audience},
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.store.CacheToken("burst-token", "alice", audience)
	h.store.RecordProviderRefresh("burst-token", "rt-0", time.Now().Add(30*time.Second))

	results := make([]string, concurrency)
	errs := make([]error, concurrency)
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_, rotated, err := h.ValidateToken(context.Background(), "burst-token", audience)
			results[idx] = rotated
			errs[idx] = err
		}(i)
	}
	// Give the goroutines time to all converge on singleflight.Do before the
	// leader's provider call returns. A short sleep is acceptable here because
	// the singleflight membership is purely a sync barrier and the leader is
	// blocked on releaseCh anyway.
	time.Sleep(50 * time.Millisecond)
	close(releaseCh)
	wg.Wait()

	if got := atomic.LoadInt32(&refreshCalls); got != 1 {
		t.Errorf("provider.RefreshToken must be called exactly once under singleflight, got %d", got)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("goroutine %d ValidateToken err: %v", i, err)
		}
	}
	for i, rotated := range results {
		if rotated != "rotated-once" {
			t.Errorf("goroutine %d rotated token: got %q, want %q", i, rotated, "rotated-once")
		}
	}
}

// TestValidateTokenGitHubRotationFailureClearsMetadata verifies that a
// permanent provider failure (e.g. bad_refresh_token) clears the cached
// provider refresh metadata so subsequent ValidateToken calls do not keep
// hammering the provider with the same poisoned refresh token. Transient
// (UpstreamError) failures must NOT clear metadata so they can be retried
// once the provider recovers.
func TestValidateTokenGitHubRotationFailureClearsMetadata(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	cases := []struct {
		name             string
		refreshFunc      func(ctx context.Context, rt string) (provider.TokenResponse, error)
		wantMetadataKept bool // true means metadata must remain intact for next retry
	}{
		{
			name: "bad_refresh_token (permanent) clears metadata",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, fmt.Errorf("bad_refresh_token")
			},
			wantMetadataKept: false,
		},
		{
			name: "ErrRefreshNotSupported clears metadata",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, provider.ErrRefreshNotSupported
			},
			wantMetadataKept: false,
		},
		{
			name: "empty access_token clears metadata",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{AccessToken: ""}, nil
			},
			wantMetadataKept: false,
		},
		{
			name: "transient UpstreamError keeps metadata for retry",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, &provider.UpstreamError{Err: fmt.Errorf("network down")}
			},
			wantMetadataKept: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := &provider.Mock{
				ClientIDValue: "test-client-id",
				ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
					return provider.Identity{Provider: "mock", Subject: "alice"}, nil
				},
				RefreshTokenFunc: tc.refreshFunc,
			}
			h, err := NewHandler(Config{
				BaseURL:              "http://localhost:8080",
				SessionTTL:           10 * time.Minute,
				CacheTTL:             5 * time.Minute,
				ExpiresIn:            90 * 24 * time.Hour,
				AllowedAudiences:     []string{audience},
				GitHubRefreshEnabled: true,
			}, p)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			h.store.CacheToken("at", "alice", audience)
			h.store.RecordProviderRefresh("at", "rt-original", time.Now().Add(30*time.Second))

			_, rotated, err := h.ValidateToken(context.Background(), "at", audience)
			if err != nil {
				t.Fatalf("ValidateToken: %v", err)
			}
			if rotated != "" {
				t.Errorf("rotated must be empty on failure, got %q", rotated)
			}
			rec, ok := h.store.LookupToken("at")
			if !ok {
				t.Fatal("token entry must still exist after rotation failure")
			}
			if tc.wantMetadataKept {
				if rec.ProviderRefreshToken != "rt-original" {
					t.Errorf("transient failure must keep refresh metadata, got %q", rec.ProviderRefreshToken)
				}
			} else {
				if rec.ProviderRefreshToken != "" {
					t.Errorf("permanent failure must clear refresh metadata, got %q", rec.ProviderRefreshToken)
				}
				if !rec.ProviderAccessExpiry.IsZero() {
					t.Errorf("permanent failure must clear access expiry, got %v", rec.ProviderAccessExpiry)
				}
			}
		})
	}
}

// TestValidateTokenGitHubRotationSkipsWhenSubjectUnknown verifies that
// rotation is skipped when the cached entry has not yet been validated
// against the provider (Subject is empty), so downstream services never see
// an anonymous identity header injected from a half-populated cache row.
func TestValidateTokenGitHubRotationSkipsWhenSubjectUnknown(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	var refreshCalls int
	var validateCalls int
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			validateCalls++
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			refreshCalls++
			return provider.TokenResponse{
				AccessToken:          "new-access",
				RefreshToken:         "rt-new",
				AccessTokenExpiresIn: 30 * time.Second,
			}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		AllowedAudiences:     []string{audience},
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	// Register the audience (mimicking tokenAuthCode) but skip CacheToken so
	// Subject stays empty. Then attach in-leeway provider metadata.
	h.store.RegisterTokenAudience("token-no-subject", audience)
	h.store.RecordProviderRefresh("token-no-subject", "rt-old", time.Now().Add(30*time.Second))

	subject, rotated, err := h.ValidateToken(context.Background(), "token-no-subject", audience)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if rotated != "" {
		t.Errorf("rotation must be skipped when subject is unknown, got rotated=%q", rotated)
	}
	if refreshCalls != 0 {
		t.Errorf("provider.RefreshToken must not be called when subject is unknown, got %d calls", refreshCalls)
	}
	if subject != "alice" {
		t.Errorf("subject after provider validation: got %q, want alice", subject)
	}
	if validateCalls != 1 {
		t.Errorf("provider.ValidateToken should be called once to populate subject, got %d", validateCalls)
	}
}

// TestValidateTokenGitHubRotationKeepsOriginalEntryRotating verifies that
// after a successful rotation, presenting the original token again triggers
// another rotation (using the rotated refresh token)  Ei.e. the original
// entry's metadata was refreshed, not cleared.
func TestValidateTokenGitHubRotationKeepsOriginalEntryRotating(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	var observed []string
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
		RefreshTokenFunc: func(_ context.Context, rt string) (provider.TokenResponse, error) {
			observed = append(observed, rt)
			return provider.TokenResponse{
				AccessToken:          fmt.Sprintf("new-access-%d", len(observed)),
				RefreshToken:         fmt.Sprintf("rt-new-%d", len(observed)),
				AccessTokenExpiresIn: 30 * time.Second,
			}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		AllowedAudiences:     []string{audience},
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.store.CacheToken("original", "alice", audience)
	h.store.RecordProviderRefresh("original", "rt-0", time.Now().Add(30*time.Second))

	// First request: rotation fires, original cache stays with refreshed metadata.
	_, rotated1, err := h.ValidateToken(context.Background(), "original", audience)
	if err != nil {
		t.Fatalf("first ValidateToken: %v", err)
	}
	if rotated1 != "new-access-1" {
		t.Fatalf("first rotation: got %q", rotated1)
	}
	// Second request from a client that still presents the original token:
	// rotation should fire again using the rotated refresh token.
	_, rotated2, err := h.ValidateToken(context.Background(), "original", audience)
	if err != nil {
		t.Fatalf("second ValidateToken: %v", err)
	}
	if rotated2 != "new-access-2" {
		t.Fatalf("second rotation off original token: got %q", rotated2)
	}
	if len(observed) != 2 {
		t.Fatalf("refresh call count: got %d, want 2", len(observed))
	}
	if observed[0] != "rt-0" || observed[1] != "rt-new-1" {
		t.Errorf("provider received refresh tokens %v; expected [rt-0 rt-new-1]", observed)
	}
}

// TestValidateTokenGitHubRotationCarriesRefreshToken verifies that a
// successful rotation carries the new refresh token forward, so the next
// rotation uses the rotated value rather than re-using the original.
func TestValidateTokenGitHubRotationCarriesRefreshToken(t *testing.T) {
	const audience = "http://localhost:8080/mcp"
	var observedRefreshTokens []string
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
		RefreshTokenFunc: func(_ context.Context, rt string) (provider.TokenResponse, error) {
			observedRefreshTokens = append(observedRefreshTokens, rt)
			return provider.TokenResponse{
				AccessToken:          fmt.Sprintf("at-%d", len(observedRefreshTokens)),
				RefreshToken:         fmt.Sprintf("rt-%d", len(observedRefreshTokens)),
				AccessTokenExpiresIn: 30 * time.Second,
			}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		AllowedAudiences:     []string{audience},
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	h.store.CacheToken("at-0", "alice", audience)
	h.store.RecordProviderRefresh("at-0", "rt-0", time.Now().Add(30*time.Second))

	_, rotated, err := h.ValidateToken(context.Background(), "at-0", audience)
	if err != nil {
		t.Fatalf("first ValidateToken: %v", err)
	}
	if rotated != "at-1" {
		t.Fatalf("first rotation: rotated token = %q, want at-1", rotated)
	}
	_, rotated2, err := h.ValidateToken(context.Background(), rotated, audience)
	if err != nil {
		t.Fatalf("second ValidateToken: %v", err)
	}
	if rotated2 != "at-2" {
		t.Fatalf("second rotation: rotated token = %q, want at-2", rotated2)
	}
	if len(observedRefreshTokens) != 2 {
		t.Fatalf("provider call count: got %d, want 2", len(observedRefreshTokens))
	}
	if observedRefreshTokens[0] != "rt-0" || observedRefreshTokens[1] != "rt-1" {
		t.Errorf("provider received refresh tokens %v; expected [rt-0 rt-1]", observedRefreshTokens)
	}
}

// TestTokenStoreSaveProviderRefreshNoEntry verifies that SaveProviderRefresh
// on an unknown token is a silent no-op rather than resurrecting an entry.
// This is the contract relied on by Store.RecordProviderRefresh to keep
// the cache from drifting after Sweep removes an expired token.
func TestTokenStoreSaveProviderRefreshNoEntry(t *testing.T) {
	store := NewMemTokenStore()
	if err := store.SaveProviderRefresh("unknown", "rt", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("SaveProviderRefresh: %v", err)
	}
	if _, ok := store.Lookup("unknown"); ok {
		t.Fatal("SaveProviderRefresh must not create a new entry for unknown token")
	}
}

func TestOIDCProviderEndpoints(t *testing.T) {
	h := newTestHandler(t)

	// 1. Test OIDC Discovery
	rDisc := httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil)
	wDisc := httptest.NewRecorder()
	h.OIDCDiscovery(wDisc, rDisc)

	if wDisc.Code != http.StatusOK {
		t.Errorf("OIDCDiscovery status: got %d, want 200", wDisc.Code)
	}
	var discDoc map[string]any
	if err := json.NewDecoder(wDisc.Body).Decode(&discDoc); err != nil {
		t.Fatalf("decoding discovery: %v", err)
	}
	if discDoc["issuer"] != "http://localhost:8080" {
		t.Errorf("issuer: got %v", discDoc["issuer"])
	}
	if discDoc["userinfo_endpoint"] != "http://localhost:8080/userinfo" {
		t.Errorf("userinfo_endpoint: got %v", discDoc["userinfo_endpoint"])
	}
	if discDoc["jwks_uri"] != "http://localhost:8080/jwks" {
		t.Errorf("jwks_uri: got %v", discDoc["jwks_uri"])
	}
	if discDoc["registration_endpoint"] != "http://localhost:8080/register" {
		t.Errorf("registration_endpoint: got %v", discDoc["registration_endpoint"])
	}
	if discDoc["device_authorization_endpoint"] != "http://localhost:8080/device_authorization" {
		t.Errorf("device_authorization_endpoint: got %v", discDoc["device_authorization_endpoint"])
	}
	assertJSONStringsContain(t, discDoc, "code_challenge_methods_supported", "S256")
	assertJSONStringsContain(t, discDoc, "grant_types_supported", "authorization_code")
	assertJSONStringsContain(t, discDoc, "grant_types_supported", "refresh_token")
	assertJSONStringsContain(t, discDoc, "grant_types_supported", "urn:ietf:params:oauth:grant-type:device_code")

	// 2. Test JWKS
	rJWKS := httptest.NewRequest(http.MethodGet, "/jwks", nil)
	wJWKS := httptest.NewRecorder()
	h.JWKS(wJWKS, rJWKS)

	if wJWKS.Code != http.StatusOK {
		t.Errorf("JWKS status: got %d, want 200", wJWKS.Code)
	}
	var jwksDoc map[string]any
	if err := json.NewDecoder(wJWKS.Body).Decode(&jwksDoc); err != nil {
		t.Fatalf("decoding JWKS: %v", err)
	}
	keys, ok := jwksDoc["keys"].([]any)
	if !ok || len(keys) == 0 {
		t.Fatalf("expected keys in JWKS: %v", jwksDoc)
	}
	key := keys[0].(map[string]any)
	if key["kty"] != "RSA" || key["alg"] != "RS256" || key["kid"] != "gateway-key-1" {
		t.Errorf("unexpected JWK fields: %v", key)
	}
	if key["n"] == "" || key["e"] == "" {
		t.Errorf("missing modulus/exponent: %v", key)
	}

	// 3. Test UserInfo - Unauthorized
	rUIUnauth := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	wUIUnauth := httptest.NewRecorder()
	h.UserInfo(wUIUnauth, rUIUnauth)
	if wUIUnauth.Code != http.StatusUnauthorized {
		t.Errorf("unauthorized userinfo status: got %d, want 401", wUIUnauth.Code)
	}

	// 4. Test UserInfo - Success
	h.store.CacheToken("my-gateway-token", "alice", "")
	rUISuccess := httptest.NewRequest(http.MethodGet, "/userinfo", nil)
	rUISuccess.Header.Set("Authorization", "Bearer my-gateway-token")
	wUISuccess := httptest.NewRecorder()
	h.UserInfo(wUISuccess, rUISuccess)

	if wUISuccess.Code != http.StatusOK {
		t.Errorf("success userinfo status: got %d, want 200; body: %s", wUISuccess.Code, wUISuccess.Body.String())
	}
	var uiDoc map[string]any
	if err := json.NewDecoder(wUISuccess.Body).Decode(&uiDoc); err != nil {
		t.Fatalf("decoding userinfo: %v", err)
	}
	if uiDoc["sub"] != "alice" {
		t.Errorf("sub: got %v, want alice", uiDoc["sub"])
	}

	// 5. Test ID Token generation during code exchange
	h.store.SaveSession("state-oidc", "http://localhost/cb", "", "http://localhost:8080", "", "")
	code, err := h.store.CompleteCallback("state-oidc", "provider-tok", "openid", "", time.Time{}, "alice")
	if err != nil {
		t.Fatalf("CompleteCallback: %v", err)
	}

	body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost/cb", code)
	rToken := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	rToken.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	wToken := httptest.NewRecorder()

	h.Token(wToken, rToken)
	if wToken.Code != http.StatusOK {
		t.Fatalf("token exchange: got status %d; body: %s", wToken.Code, wToken.Body.String())
	}

	var tokenResp map[string]any
	if err := json.NewDecoder(wToken.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decoding token response: %v", err)
	}

	idToken, ok := tokenResp["id_token"].(string)
	if !ok || idToken == "" {
		t.Fatal("expected id_token in response when openid scope requested")
	}

	// Verify id_token JWT structure
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid JWT format: got %d parts, want 3", len(parts))
	}

	// Verify claims
	payloadDecoded, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payloadDecoded, &claims); err != nil {
		t.Fatalf("unmarshaling payload: %v", err)
	}
	if claims["sub"] != "alice" || claims["iss"] != "http://localhost:8080" || claims["aud"] != "test-client-id" {
		t.Errorf("unexpected payload claims: %v", claims)
	}

	// Verify signature
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding signature: %v", err)
	}
	signingInput := parts[0] + "." + parts[1]
	hasher := sha256.New()
	hasher.Write([]byte(signingInput))
	hashed := hasher.Sum(nil)

	pubKey := h.privateKey.Public().(*rsa.PublicKey)
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed, sig); err != nil {
		t.Errorf("signature verification failed: %v", err)
	}
}

func TestIDTokenNonceClaim(t *testing.T) {
	tests := []struct {
		name          string
		nonce         string
		expectInToken bool
	}{
		{"nonce present", "test-nonce-value-abc123", true},
		{"nonce absent", "", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHandler(t)
			h.store.SaveSession("state-nonce", "http://localhost/cb", "", "http://localhost:8080", tc.nonce, "")
			code, err := h.store.CompleteCallback("state-nonce", "provider-tok", "openid", "", time.Time{}, "alice")
			if err != nil {
				t.Fatalf("CompleteCallback: %v", err)
			}

			body := fmt.Sprintf("grant_type=authorization_code&code=%s&redirect_uri=http://localhost/cb", code)
			r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.Token(w, r)
			if w.Code != http.StatusOK {
				t.Fatalf("token exchange: got status %d; body: %s", w.Code, w.Body.String())
			}

			var tokenResp map[string]any
			if err := json.NewDecoder(w.Body).Decode(&tokenResp); err != nil {
				t.Fatalf("decoding token response: %v", err)
			}
			idToken, ok := tokenResp["id_token"].(string)
			if !ok || idToken == "" {
				t.Fatal("expected id_token in response")
			}

			parts := strings.Split(idToken, ".")
			if len(parts) != 3 {
				t.Fatalf("invalid JWT format: got %d parts", len(parts))
			}
			payloadDecoded, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("decoding payload: %v", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payloadDecoded, &claims); err != nil {
				t.Fatalf("unmarshaling payload: %v", err)
			}

			nonceClaim, hasClaim := claims["nonce"]
			if tc.expectInToken {
				if !hasClaim {
					t.Error("expected nonce claim in id_token, but not found")
				} else if nonceClaim != tc.nonce {
					t.Errorf("nonce claim: got %v, want %v", nonceClaim, tc.nonce)
				}
			} else {
				if hasClaim {
					t.Errorf("expected no nonce claim in id_token, but got %v", nonceClaim)
				}
			}
		})
	}
}

// TestTokenRefreshNoncePropagated verifies that the nonce from the original
// authorization request is forwarded in the id_token issued by the refresh
// endpoint (OIDC Core §12.2). Tested in builtin mode where id_token is always
// emitted on refresh.
func TestTokenRefreshNoncePropagated(t *testing.T) {
	tests := []struct {
		name           string
		nonce          string
		expireATBefore bool // simulate AT TTL expiry before refresh
		expectInToken  bool
	}{
		{"nonce present", "original-nonce-xyz", false, true},
		{"nonce absent", "", false, false},
		// Thread-owl PRRT_kwDOSNXuJs6KuAH4: nonce must survive past the AT TTL
		// because the refresh token grace period exceeds the access token TTL.
		{"nonce present, AT store expired", "original-nonce-xyz", true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newBuiltinTestHandler(t,
				func(_ context.Context, _ string) (provider.TokenResponse, error) {
					return provider.TokenResponse{AccessToken: "gh-tok"}, nil
				},
				func(_ context.Context, _ string) (provider.Identity, error) {
					return provider.Identity{Subject: "alice"}, nil
				},
			)

			// Authorize → Callback → Token (authorization_code) with nonce.
			verifier := "test-verifier-abcdefghijklmnopqrstuvwxyz01234"
			challenge := pkceChallenge(verifier)
			state := "nonce-test-state"
			redirectURI := "http://localhost/cb"

			authURL := "/authorize?response_type=code&state=" + state +
				"&redirect_uri=" + url.QueryEscape(redirectURI) +
				"&code_challenge=" + challenge +
				"&code_challenge_method=S256"
			if tc.nonce != "" {
				authURL += "&nonce=" + url.QueryEscape(tc.nonce)
			}
			h.Authorize(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, authURL, nil))

			cbRec := httptest.NewRecorder()
			h.Callback(cbRec, httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil))
			if cbRec.Code != http.StatusFound {
				t.Fatalf("callback: got %d", cbRec.Code)
			}
			loc, _ := url.Parse(cbRec.Header().Get("Location"))
			internalCode := loc.Query().Get("code")

			tokenBody := "grant_type=authorization_code" +
				"&redirect_uri=" + url.QueryEscape(redirectURI) +
				"&code=" + url.QueryEscape(internalCode) +
				"&code_verifier=" + url.QueryEscape(verifier)
			tokenRec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			h.Token(tokenRec, req)
			if tokenRec.Code != http.StatusOK {
				t.Fatalf("token exchange: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
			}
			var tokenResp map[string]any
			if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
				t.Fatalf("decode token response: %v", err)
			}
			rt, _ := tokenResp["refresh_token"].(string)
			if rt == "" {
				t.Fatal("expected refresh_token in authorization_code response")
			}

			if tc.expireATBefore {
				// Simulate the access-token TTL expiring before the refresh-token
				// grace period (PRRT_kwDOSNXuJs6KuAH4): the AT record is evicted
				// from the token store while the RT is still valid. Nonce must
				// still be propagated via the RT-keyed entry.
				at, _ := tokenResp["access_token"].(string)
				h.store.InvalidateCachedToken(at)
			}

			// Refresh — nonce must be propagated to the new id_token.
			refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
			refreshRec := httptest.NewRecorder()
			req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
			req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			h.Token(refreshRec, req2)
			if refreshRec.Code != http.StatusOK {
				t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
			}
			var refreshResp map[string]any
			if err := json.NewDecoder(refreshRec.Body).Decode(&refreshResp); err != nil {
				t.Fatalf("decode refresh response: %v", err)
			}

			idToken, _ := refreshResp["id_token"].(string)
			if idToken == "" {
				t.Fatal("expected id_token in refresh response (builtin mode always issues id_token)")
			}
			parts := strings.Split(idToken, ".")
			if len(parts) != 3 {
				t.Fatalf("invalid JWT: got %d parts", len(parts))
			}
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				t.Fatalf("decode JWT payload: %v", err)
			}
			var claims map[string]any
			if err := json.Unmarshal(payload, &claims); err != nil {
				t.Fatalf("unmarshal claims: %v", err)
			}

			nonceClaim, hasClaim := claims["nonce"]
			if tc.expectInToken {
				if !hasClaim {
					t.Error("expected nonce claim in refresh id_token, but not found")
				} else if nonceClaim != tc.nonce {
					t.Errorf("nonce claim: got %v, want %q", nonceClaim, tc.nonce)
				}
			} else {
				if hasClaim {
					t.Errorf("expected no nonce claim in refresh id_token, but got %v", nonceClaim)
				}
			}
		})
	}
}

// TestTokenRefreshNoncePropagatedChained verifies that the nonce is correctly
// propagated across multiple consecutive refresh operations (RT rotation).
// PRRT_kwDOSNXuJs6KuAH4 follow-up: after the first refresh the new RT must
// also carry the nonce so the second refresh can include it in id_token.
func TestTokenRefreshNoncePropagatedChained(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)

	const nonce = "chained-nonce-xyz"
	verifier := "test-verifier-abcdefghijklmnopqrstuvwxyz01234"
	challenge := pkceChallenge(verifier)
	state := "chained-nonce-state"
	redirectURI := "http://localhost/cb"

	authURL := "/authorize?response_type=code&state=" + state +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code_challenge=" + challenge +
		"&code_challenge_method=S256" +
		"&nonce=" + url.QueryEscape(nonce)
	h.Authorize(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, authURL, nil))

	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil))
	loc, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := loc.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenRec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.Token(tokenRec, req)
	var tokenResp map[string]any
	if err := json.NewDecoder(tokenRec.Body).Decode(&tokenResp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	rt1, _ := tokenResp["refresh_token"].(string)
	if rt1 == "" {
		t.Fatal("expected refresh_token in authorization_code response")
	}

	doRefresh := func(t *testing.T, rt string) (newRT string, nonceClaim string) {
		t.Helper()
		refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
		refreshRec := httptest.NewRecorder()
		req2 := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
		req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.Token(refreshRec, req2)
		if refreshRec.Code != http.StatusOK {
			t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
		}
		var resp map[string]any
		if err := json.NewDecoder(refreshRec.Body).Decode(&resp); err != nil {
			t.Fatalf("decode refresh response: %v", err)
		}
		idToken, _ := resp["id_token"].(string)
		if idToken == "" {
			t.Fatal("expected id_token in refresh response (builtin mode)")
		}
		claims := parseJWTPayload(t, idToken)
		nc, _ := claims["nonce"].(string)
		nr, _ := resp["refresh_token"].(string)
		return nr, nc
	}

	rt2, nonce1 := doRefresh(t, rt1)
	if nonce1 != nonce {
		t.Errorf("1st refresh: nonce claim got %q, want %q", nonce1, nonce)
	}
	if rt2 == "" {
		t.Fatal("expected refresh_token in 1st refresh response")
	}

	_, nonce2 := doRefresh(t, rt2)
	if nonce2 != nonce {
		t.Errorf("2nd refresh: nonce claim got %q, want %q (nonce must survive RT rotation)", nonce2, nonce)
	}
}

func assertJSONStringsContain(t *testing.T, doc map[string]any, key, want string) {
	t.Helper()

	values, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("%s: got %T, want JSON string array", key, doc[key])
	}
	for _, value := range values {
		if value == want {
			return
		}
	}
	t.Fatalf("%s: got %v, want value %q", key, values, want)
}

func TestNewHandler_OIDCPrivateKey(t *testing.T) {
	// Generate a key to pass into Config
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	cfg := Config{
		BaseURL:        "http://localhost:8080",
		OIDCPrivateKey: privKey,
	}

	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID: "test-client-id",
	})
	h, err := NewHandler(cfg, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	if h.privateKey != privKey {
		t.Error("expected Handler to use the provided OIDCPrivateKey")
	}

	// Now check if it works without providing a key (should generate one)
	cfgNoKey := Config{
		BaseURL: "http://localhost:8080",
	}
	hNoKey, err := NewHandler(cfgNoKey, p)
	if err != nil {
		t.Fatalf("NewHandler (no key): %v", err)
	}
	if hNoKey.privateKey == nil {
		t.Error("expected Handler to generate a random key when OIDCPrivateKey is nil")
	}
}

func TestAuthorizeCustomSchemeRedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		redirectURI string
		schemes     []string // nil = use default
		wantStatus  int
	}{
		{
			name:        "antigravity scheme accepted by default",
			redirectURI: "antigravity://oauth-callback",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "antigravity-insiders scheme accepted by default",
			redirectURI: "antigravity-insiders://oauth-callback",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "unknown custom scheme rejected",
			redirectURI: "myapp://callback",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "custom scheme allowed when explicitly configured",
			redirectURI: "myapp://callback",
			schemes:     []string{"myapp"},
			wantStatus:  http.StatusFound,
		},
		{
			name:        "http scheme still works",
			redirectURI: "http://localhost/callback",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "https scheme still works",
			redirectURI: "https://antigravity.google/oauth-callback",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "custom scheme with explicit empty list rejects antigravity",
			redirectURI: "antigravity://oauth-callback",
			schemes:     []string{"other"},
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "opaque-form custom scheme accepted when scheme is allowed",
			redirectURI: "antigravity:/oauth2redirect/provider",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "opaque-form custom scheme rejected when scheme not allowed",
			redirectURI: "myapp:/oauth2redirect/provider",
			wantStatus:  http.StatusBadRequest,
		},
		{
			name:        "opaque-form custom scheme accepted when scheme explicitly configured",
			redirectURI: "com.example.app:/oauth2redirect/provider",
			schemes:     []string{"com.example.app"},
			wantStatus:  http.StatusFound,
		},
		// true opaque form (scheme:opaque, no leading slash — exercises the Opaque branch)
		{
			name:        "true opaque form accepted when scheme is allowed",
			redirectURI: "antigravity:callback",
			wantStatus:  http.StatusFound,
		},
		{
			name:        "true opaque form rejected when scheme not allowed",
			redirectURI: "myapp:callback",
			wantStatus:  http.StatusBadRequest,
		},
		// scheme-only URI (host == "" && path == "" && opaque == "") must be rejected
		{
			name:        "custom scheme URI with no path or opaque rejected",
			redirectURI: "antigravity:",
			wantStatus:  http.StatusBadRequest,
		},
		// http/https without host must be rejected
		{
			name:        "http scheme without host rejected",
			redirectURI: "http:/no-authority-path",
			wantStatus:  http.StatusBadRequest,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := provider.NewGitHub(provider.GitHubConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				RedirectURI:  "http://localhost:8080/callback",
				Scopes:       "repo,user",
			})
			cfg := Config{
				BaseURL:    "http://localhost:8080",
				SessionTTL: 10 * time.Minute,
				CacheTTL:   5 * time.Minute,
				ExpiresIn:  90 * 24 * time.Hour,
			}
			if tc.schemes != nil {
				cfg.AllowedRedirectSchemes = tc.schemes
			}
			h, err := NewHandler(cfg, p)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}

			r := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&state=teststate&redirect_uri="+url.QueryEscape(tc.redirectURI), nil)
			w := httptest.NewRecorder()
			h.Authorize(w, r)

			if w.Code != tc.wantStatus {
				t.Errorf("status: got %d, want %d; body: %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestAuthorizeCustomSchemeDefaultSchemes(t *testing.T) {
	h := newTestHandler(t)

	// チE��ォルト�E AllowedRedirectSchemes が正しく設定されてぁE��か検証
	wantSchemes := []string{"antigravity", "antigravity-insiders"}
	for _, scheme := range wantSchemes {
		t.Run("default includes "+scheme, func(t *testing.T) {
			redirectURI := scheme + "://oauth-callback"
			r := httptest.NewRequest(http.MethodGet, "/authorize?response_type=code&state=s&redirect_uri="+url.QueryEscape(redirectURI), nil)
			w := httptest.NewRecorder()
			h.Authorize(w, r)
			if w.Code != http.StatusFound {
				t.Errorf("scheme %q should be accepted by default, got status %d", scheme, w.Code)
			}
		})
	}
}

// newBuiltinTestHandler creates a Handler in builtin mode (provider.Name() == "builtin")
// with the given GitHub exchange and identity functions.
func newBuiltinTestHandler(t *testing.T, ghExchange func(context.Context, string) (provider.TokenResponse, error), ghValidate func(context.Context, string) (provider.Identity, error)) *Handler {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &provider.Mock{
		NameValue:        "builtin",
		ClientIDValue:    "builtin-client-id",
		ScopesValue:      "read:user,user:email",
		ExchangeCodeFunc: ghExchange,
		ValidateFunc:     ghValidate,
	}
	h, err := NewHandler(Config{
		BaseURL:        "http://localhost:8080",
		SessionTTL:     10 * time.Minute,
		CacheTTL:       5 * time.Minute,
		ExpiresIn:      90 * 24 * time.Hour,
		OIDCPrivateKey: key,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// pkceChallenge returns a PKCE S256 code_challenge for the given verifier.
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// parseJWTPayload base64url-decodes the JWT payload and unmarshals it.
func parseJWTPayload(t *testing.T, token string) map[string]any {
	t.Helper()
	parts := strings.SplitN(token, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	b, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("JWT payload decode: %v", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(b, &claims); err != nil {
		t.Fatalf("JWT payload parse: %v", err)
	}
	return claims
}

func TestBuiltinAuthorizeRedirectsToGitHub(t *testing.T) {
	const ghAccessToken = "gh-access-token-must-not-leak"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, code string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "testuser"}, nil
		},
	)

	// AuthorizeURL with PKCE challenge and state
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	r := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=teststate&redirect_uri=http://localhost/cb"+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	w := httptest.NewRecorder()
	h.Authorize(w, r)

	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d, want %d; body=%s", w.Code, http.StatusFound, w.Body.String())
	}
	loc := w.Header().Get("Location")
	if !strings.Contains(loc, "state=teststate") {
		t.Errorf("location missing state: %q", loc)
	}
	// GitHub classic OAuth ignores code_challenge, but the URL must not contain it
	// or the gateway silently drops PKCE enforcement; we only verify redirect target.
	if !strings.Contains(loc, "github.com") && !strings.Contains(loc, "mock.example.com") {
		t.Errorf("unexpected redirect target: %q", loc)
	}
}

func TestBuiltinTokenFlowIssuesGatewayJWT(t *testing.T) {
	const ghAccessToken = "gh-access-token-must-not-leak"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)

	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	const state = "builtin-state"
	const redirectURI = "http://localhost/cb"

	// 1. authorize
	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	authRec := httptest.NewRecorder()
	h.Authorize(authRec, authReq)
	if authRec.Code != http.StatusFound {
		t.Fatalf("authorize: got %d", authRec.Code)
	}

	// 2. callback (GitHub sends code back)
	cbReq := httptest.NewRequest(http.MethodGet,
		"/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback: got %d; body=%s", cbRec.Code, cbRec.Body.String())
	}
	redirectURL, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	internalCode := redirectURL.Query().Get("code")
	if internalCode == "" {
		t.Fatal("callback redirect missing internal code")
	}

	// 3. token exchange
	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(tokenRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}

	// access_token must be a gateway JWT, not the GitHub token
	accessToken, _ := resp["access_token"].(string)
	if accessToken == "" {
		t.Fatal("token response missing access_token")
	}
	if accessToken == ghAccessToken {
		t.Error("access_token must not be the GitHub access token")
	}
	// gateway JWT has 3 dot-separated parts
	if strings.Count(accessToken, ".") != 2 {
		t.Errorf("access_token is not a JWT: %q", accessToken)
	}

	// refresh_token must be present
	if rt, _ := resp["refresh_token"].(string); rt == "" {
		t.Error("token response missing refresh_token")
	}

	// id_token must be present in builtin mode
	idToken, _ := resp["id_token"].(string)
	if idToken == "" {
		t.Error("token response missing id_token")
	}
}

// issueBuiltinTokens drives the full authorize -> callback -> token exchange
// flow in builtin mode and returns the issued gateway JWT (access_token) and
// opaque refresh_token. subject is the identity the mock GitHub provider
// resolves the flow to.
func issueBuiltinTokens(t *testing.T, h *Handler, subject string) (accessToken, refreshToken string) {
	t.Helper()
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := pkceChallenge(verifier)
	state := "state-" + subject
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback: got %d; body=%s", cbRec.Code, cbRec.Body.String())
	}
	redirectURL, err := url.Parse(cbRec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("parse callback redirect: %v", err)
	}
	internalCode := redirectURL.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(tokenRec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	accessToken, _ = resp["access_token"].(string)
	refreshToken, _ = resp["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("token response missing access_token/refresh_token: %#v", resp)
	}
	return accessToken, refreshToken
}

// revokeRequest issues a POST /revoke with the given token and optional hint
// and returns the recorder for assertions.
func revokeRequest(h *Handler, token, hint string) *httptest.ResponseRecorder {
	body := "token=" + url.QueryEscape(token)
	if hint != "" {
		body += "&token_type_hint=" + url.QueryEscape(hint)
	}
	req := httptest.NewRequest(http.MethodPost, "/revoke", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Revoke(rec, req)
	return rec
}

func TestRevokeMissingTokenReturns400(t *testing.T) {
	h := newTestHandler(t)
	rec := revokeRequest(h, "", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", rec.Code, http.StatusBadRequest)
	}
}

// TestRevokeBuiltinAccessTokenRejectsCacheMiss verifies that revoking a
// gateway JWT (builtin mode) via token_type_hint=access_token causes a
// subsequent ValidateToken cache-miss verification to fail, even though the
// JWT's own exp claim has not yet passed.
func TestRevokeBuiltinAccessTokenRejectsCacheMiss(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, _ := issueBuiltinTokens(t, h, "alice")

	rec := revokeRequest(h, accessToken, "access_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	// Force a cache miss: strip the cache entry the token exchange created,
	// simulating a request that arrives after the in-memory cache entry has
	// been evicted (e.g. a different process, or after eviction) — the jti
	// denylist, not the cache, is what must reject it.
	h.store.InvalidateCachedToken(accessToken)

	if _, _, err := h.ValidateToken(context.Background(), accessToken, ""); err == nil {
		t.Error("ValidateToken: expected error for revoked JWT on cache-miss path, got nil")
	}
}

// TestRevokeBuiltinAccessTokenRejectsCacheHit verifies the cache-hit path
// also honours the denylist: a token that was cached (e.g. by a prior
// request) before being revoked must not keep validating for the remainder
// of its cache TTL.
func TestRevokeBuiltinAccessTokenRejectsCacheHit(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, _ := issueBuiltinTokens(t, h, "alice")

	// Prime the cache (cache-hit path) before revoking.
	if _, _, err := h.ValidateToken(context.Background(), accessToken, ""); err != nil {
		t.Fatalf("priming ValidateToken: %v", err)
	}

	rec := revokeRequest(h, accessToken, "access_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	if _, _, err := h.ValidateToken(context.Background(), accessToken, ""); err == nil {
		t.Error("ValidateToken: expected error for revoked JWT on cache-hit path, got nil")
	}
}

// TestRevokeRefreshTokenCascadesFamilyAndCurrentAccessToken verifies that
// revoking a refresh token (a) blocks future rotation of its family and (b)
// immediately denylists the jti of the access token currently associated
// with that family, rather than leaving it valid until its own exp.
func TestRevokeRefreshTokenCascadesFamilyAndCurrentAccessToken(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, refreshToken := issueBuiltinTokens(t, h, "alice")

	rec := revokeRequest(h, refreshToken, "refresh_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	// (a) the refresh token itself can no longer be used for rotation.
	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code == http.StatusOK {
		t.Errorf("refresh grant with revoked refresh_token unexpectedly succeeded: %s", refreshRec.Body.String())
	}

	// (b) the access token issued alongside it is also immediately rejected,
	// not just when it would eventually be rotated.
	h.store.InvalidateCachedToken(accessToken)
	if _, _, err := h.ValidateToken(context.Background(), accessToken, ""); err == nil {
		t.Error("ValidateToken: expected error for access token cascaded from refresh token revocation")
	}
}

// TestRevokeIdempotentAndUnknownTokens verifies RFC 7009 §2.2: revoking an
// unknown, already-expired, or already-revoked token is not an error — the
// endpoint always responds 200 so a caller cannot use it to probe validity.
func TestRevokeIdempotentAndUnknownTokens(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, _ := issueBuiltinTokens(t, h, "alice")

	if rec := revokeRequest(h, "totally-unknown-opaque-token", ""); rec.Code != http.StatusOK {
		t.Errorf("revoke unknown token: got %d, want 200", rec.Code)
	}
	if rec := revokeRequest(h, "not.a.jwt", ""); rec.Code != http.StatusOK {
		t.Errorf("revoke malformed token: got %d, want 200", rec.Code)
	}
	// Double revoke of the same valid token must also succeed both times.
	if rec := revokeRequest(h, accessToken, "access_token"); rec.Code != http.StatusOK {
		t.Errorf("first revoke: got %d, want 200", rec.Code)
	}
	if rec := revokeRequest(h, accessToken, "access_token"); rec.Code != http.StatusOK {
		t.Errorf("second (duplicate) revoke: got %d, want 200", rec.Code)
	}
}

// TestRevokeRefreshTokenWithEmptyFamilyIDStillRevokesToken verifies that a
// refresh token issued with familyID == "" (the best-effort fallback in
// tokenAuthCode/tokenDeviceGrant when family-ID generation fails) is still
// individually invalidated by /revoke. Before this fix, /revoke only called
// RevokeRefreshTokenFamily, which is a no-op for an empty familyID, leaving
// the presented token itself usable after a 200 response (thread-owl review,
// PR #195).
func TestRevokeRefreshTokenWithEmptyFamilyIDStillRevokesToken(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, _ := issueBuiltinTokens(t, h, "alice")
	// Simulate the familyID-generation-failure fallback directly: create a
	// second refresh token for the same access token with familyID = "".
	rt, err := h.store.CreateRefreshToken(accessToken, "", "", h.refreshTokenTTL())
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	rec := revokeRequest(h, rt, "refresh_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(rt)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code == http.StatusOK {
		t.Errorf("refresh grant with revoked (empty-familyID) refresh_token unexpectedly succeeded: %s", refreshRec.Body.String())
	}
}

// TestRevokeStaleRefreshTokenCascadesToCurrentAccessToken verifies that
// revoking an already-rotated (stale) refresh token still finds and denylists
// the CURRENT access token for that family, not just the older JWT recorded
// on the stale token's own row. Before this fix, LookupAnyRefreshToken's
// accessToken field pointed at the predecessor JWT minted before rotation,
// so the live JWT actually in use remained valid (thread-owl review, PR #195).
func TestRevokeStaleRefreshTokenCascadesToCurrentAccessToken(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	_, refreshToken1 := issueBuiltinTokens(t, h, "alice")

	// Rotate once: refreshToken1 becomes stale, and a new access/refresh
	// token pair is issued in the same family.
	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken1)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("rotation: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp map[string]any
	if err := json.NewDecoder(refreshRec.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("decode rotation response: %v", err)
	}
	accessToken2, _ := refreshResp["access_token"].(string)
	if accessToken2 == "" {
		t.Fatal("rotation response missing access_token")
	}

	// Revoke the STALE (pre-rotation) refresh token.
	rec := revokeRequest(h, refreshToken1, "refresh_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	// The CURRENT access token (accessToken2), not just the original one,
	// must now be rejected.
	h.store.InvalidateCachedToken(accessToken2)
	if _, _, err := h.ValidateToken(context.Background(), accessToken2, ""); err == nil {
		t.Error("ValidateToken: expected error for current access token cascaded from a stale refresh token revocation")
	}
}

// TestRevokeStaleRefreshTokenFindsCurrentAccessTokenDuringConcurrentReservation
// pins the exact race thread-owl flagged in the second review round: a row
// scan for "the non-revoked row in this family" finds nothing during the
// narrow window where a concurrent rotation has reserved (soft-revoked) the
// current refresh token but has not yet committed its replacement row. The
// family_current_access_token pointer must still resolve to the access token
// actually in the client's hands (accessToken2), not the stale
// predecessor (accessToken1) and not "" (thread-owl review, PR #195).
func TestRevokeStaleRefreshTokenFindsCurrentAccessTokenDuringConcurrentReservation(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	_, refreshToken1 := issueBuiltinTokens(t, h, "alice")

	// Rotation 1, via the normal HTTP path: refreshToken1 -> accessToken2/refreshToken2.
	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken1)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("rotation 1: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var resp1 map[string]any
	if err := json.NewDecoder(refreshRec.Body).Decode(&resp1); err != nil {
		t.Fatalf("decode rotation 1 response: %v", err)
	}
	accessToken2, _ := resp1["access_token"].(string)
	refreshToken2, _ := resp1["refresh_token"].(string)
	if accessToken2 == "" || refreshToken2 == "" {
		t.Fatalf("rotation 1 response missing tokens: %#v", resp1)
	}

	// Simulate rotation 2 currently in flight: refreshToken2 has been
	// reserved (soft-revoked) but its replacement row has not been created
	// yet. ReserveRefreshToken is exactly what tokenRefresh calls internally
	// before minting the next access/refresh token pair.
	if _, _, _, _, err := h.store.ReserveRefreshToken(refreshToken2); err != nil {
		t.Fatalf("ReserveRefreshToken: %v", err)
	}

	// Revoke the now-stale refreshToken1 while rotation 2 is mid-flight.
	rec := revokeRequest(h, refreshToken1, "refresh_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	// accessToken2 — the token actually held by the client at this point —
	// must be rejected, even though no non-revoked refresh_tokens row
	// exists for the family right now.
	h.store.InvalidateCachedToken(accessToken2)
	if _, _, err := h.ValidateToken(context.Background(), accessToken2, ""); err == nil {
		t.Error("ValidateToken: expected error for accessToken2 despite the concurrent reservation window")
	}
}

// recordingTokenStore wraps a TokenStore, recording every token passed to
// Save so a test can capture a provisional token minted mid-request without
// the handler ever returning it.
type recordingTokenStore struct {
	TokenStore
	mu    sync.Mutex
	saved []string
}

func (r *recordingTokenStore) Save(token, subject string, audiences []string, expiresAt time.Time) error {
	r.mu.Lock()
	r.saved = append(r.saved, token)
	r.mu.Unlock()
	return r.TokenStore.Save(token, subject, audiences, expiresAt)
}

func (r *recordingTokenStore) lastSaved() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.saved) == 0 {
		return ""
	}
	return r.saved[len(r.saved)-1]
}

// revokeFamilyOnFirstSave wraps a RefreshTokenStore and, on the first Save
// call carrying a non-empty familyID, first revokes that family on the
// underlying store before delegating — deterministically simulating a
// concurrent POST /revoke whose RevokeFamily transaction commits at the
// exact instant a rotation's own Save (guarded against the same tombstone)
// is about to run. This reproduces the race window from a single goroutine,
// without depending on real scheduling.
type revokeFamilyOnFirstSave struct {
	RefreshTokenStore
	fired bool
}

func (r *revokeFamilyOnFirstSave) Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error {
	if !r.fired && familyID != "" {
		r.fired = true
		if _, err := r.RevokeFamily(familyID); err != nil {
			panic(fmt.Sprintf("test setup: RevokeFamily: %v", err))
		}
	}
	return r.RefreshTokenStore.Save(refreshToken, accessToken, audience, familyID, expiresAt)
}

// TestRevokeConcurrentRotationDoesNotLeakProvisionalToken pins the second
// finding from thread-owl's review: when a rotation's CreateRefreshToken
// fails because its family was concurrently revoked, the gateway JWT already
// cached (with its provider access token and subject-index entry) before
// that failure must not survive — otherwise it remains reachable via
// EnsureFreshAccessTokenForSubject (Phase B delegated access) even though
// the client never received it and /revoke was supposed to cut off access
// (thread-owl review, PR #195).
func TestRevokeConcurrentRotationDoesNotLeakProvisionalToken(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	_, refreshToken1 := issueBuiltinTokens(t, h, "alice")

	// Swap in a recording TokenStore (to capture the provisional token) and
	// a RefreshTokenStore that revokes refreshToken1's family the instant
	// the rotation below tries to Save its replacement row — simulating a
	// concurrent /revoke landing in the middle of this rotation. The
	// underlying refresh-token store is preserved as-is (it already holds
	// refreshToken1). The OAuth session/PKCE bookkeeping used only during
	// Authorize->Callback->Token is no longer needed at this point.
	rec := &recordingTokenStore{TokenStore: NewMemTokenStore()}
	wrappedRefresh := &revokeFamilyOnFirstSave{RefreshTokenStore: h.store.refreshStore}
	h.store = NewStore(10*time.Minute, 90*24*time.Hour, rec, WithRefreshTokenStore(wrappedRefresh))

	// Attempt rotation via refreshToken1. ReserveRefreshToken succeeds
	// normally (the family is not yet tombstoned), but by the time
	// CreateRefreshToken tries to Save the new row, revokeFamilyOnFirstSave
	// has already tombstoned the family — exactly the outcome a real
	// concurrent /revoke call racing this rotation would produce.
	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken1)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusBadRequest {
		t.Fatalf("rotation racing a concurrent revoke: got %d, want 400; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	if !wrappedRefresh.fired {
		t.Fatal("setup: expected the concurrent-revoke hook to have fired")
	}

	provisional := rec.lastSaved()
	if provisional == "" {
		t.Fatal("setup: expected a provisional token to have been generated and Saved")
	}
	if _, ok := h.store.LookupToken(provisional); ok {
		t.Error("provisional gateway JWT must be invalidated after CreateRefreshToken fails due to a concurrently revoked family")
	}
}

// revokeJTIFailStore wraps a RefreshTokenStore, delegating everything except
// RevokeJTI, which always fails — simulating a denylist write failure (e.g.
// SQLite read-only/locked/corrupt) to verify /revoke does not report success
// when the security property it promises could not actually be persisted.
type revokeJTIFailStore struct {
	RefreshTokenStore
}

func (r *revokeJTIFailStore) RevokeJTI(_ string, _ time.Time) error {
	return fmt.Errorf("simulated jti denylist write failure")
}

// TestRevokeStoreWriteFailurePropagatesAsServerError verifies that a failed
// RevokeJTI write is surfaced as 500 server_error rather than 200 — silently
// reporting success would leave the JWT re-validating after the next cache
// eviction (thread-owl review, PR #195).
func TestRevokeStoreWriteFailurePropagatesAsServerError(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	)
	accessToken, _ := issueBuiltinTokens(t, h, "alice")

	// Swap in a RefreshTokenStore whose RevokeJTI always fails, simulating a
	// denylist write failure discovered only once /revoke is called. The
	// OAuth session/PKCE bookkeeping used only during Authorize->Callback->
	// Token is no longer needed at this point, so replacing the whole store
	// (rather than mutating it in place, which Store does not expose) is safe.
	h.store = NewStore(10*time.Minute, 90*24*time.Hour, NewMemTokenStore(),
		WithRefreshTokenStore(&revokeJTIFailStore{RefreshTokenStore: NewMemRefreshTokenStore()}))

	rec := revokeRequest(h, accessToken, "access_token")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("revoke with failing denylist write: got %d, want 500; body=%s", rec.Code, rec.Body.String())
	}
}

// TestRevokeNonBuiltinModeInvalidatesCache verifies that in non-builtin mode
// (cache key = provider access token), /revoke removes the cached entry so a
// subsequent request re-validates against the upstream provider rather than
// trusting a stale cache hit.
func TestRevokeNonBuiltinModeInvalidatesCache(t *testing.T) {
	h := newTestHandler(t)
	h.store.CacheToken("gh-access-token", "carol", "http://localhost:8080/mcp")
	if _, ok := h.store.LookupToken("gh-access-token"); !ok {
		t.Fatal("setup: expected cache hit before revoke")
	}

	rec := revokeRequest(h, "gh-access-token", "access_token")
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: got %d; body=%s", rec.Code, rec.Body.String())
	}

	if _, ok := h.store.LookupToken("gh-access-token"); ok {
		t.Error("expected cache entry to be removed after /revoke")
	}
}

// TestDiscoveryIncludesRevocationEndpoint verifies RFC 8414 discovery
// advertises the revocation_endpoint so clients can find it.
func TestDiscoveryIncludesRevocationEndpoint(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil)
	rec := httptest.NewRecorder()
	h.Discovery(rec, req)

	var doc map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery doc: %v", err)
	}
	want := h.cfg.BaseURL + "/revoke"
	if got, _ := doc["revocation_endpoint"].(string); got != want {
		t.Errorf("revocation_endpoint: got %q, want %q", got, want)
	}
}

func TestBuiltinGitHubAccessTokenNotLeaked(t *testing.T) {
	const ghAccessToken = "SUPER_SECRET_GITHUB_TOKEN"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "bob"}, nil
		},
	)

	verifier := "test-verifier-12345678901234567890123456789012"
	challenge := pkceChallenge(verifier)
	const state = "leak-test-state"
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	redirectURL, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := redirectURL.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)

	body := tokenRec.Body.String()
	if strings.Contains(body, ghAccessToken) {
		t.Errorf("token response must not contain GitHub access token, got body: %s", body)
	}
}

func TestBuiltinIDTokenClaims(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "charlie"}, nil
		},
	)

	verifier := "test-verifier-abcdefghijklmnopqrstuvwxyz12345"
	challenge := pkceChallenge(verifier)
	const state = "claims-test-state"
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	redirectURL, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := redirectURL.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)

	var resp map[string]any
	_ = json.NewDecoder(tokenRec.Body).Decode(&resp)

	idToken, _ := resp["id_token"].(string)
	if idToken == "" {
		t.Fatal("missing id_token")
	}
	claims := parseJWTPayload(t, idToken)

	for _, key := range []string{"iss", "sub", "aud", "exp", "iat"} {
		if claims[key] == nil {
			t.Errorf("id_token missing claim %q", key)
		}
	}
	if sub, _ := claims["sub"].(string); sub != "charlie" {
		t.Errorf("id_token sub: got %q, want %q", sub, "charlie")
	}
	if iss, _ := claims["iss"].(string); iss != "http://localhost:8080" {
		t.Errorf("id_token iss: got %q, want %q", iss, "http://localhost:8080")
	}
}

func TestBuiltinStateMismatchRejected(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "dave"}, nil
		},
	)
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state=real-state&redirect_uri="+url.QueryEscape(redirectURI), nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	// callback with wrong state
	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state=wrong-state", nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusBadRequest {
		t.Errorf("state mismatch: got %d, want %d", cbRec.Code, http.StatusBadRequest)
	}
}

func TestBuiltinCodeVerifierMismatchRejected(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "eve"}, nil
		},
	)

	verifier := "correct-verifier-abcdefghijklmnopqrstuvwxyz01"
	challenge := pkceChallenge(verifier)
	const state = "pkce-test-state"
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	redirectURL, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := redirectURL.Query().Get("code")

	// wrong verifier
	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=wrong-verifier"
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusBadRequest {
		t.Errorf("PKCE mismatch: got %d, want %d; body=%s", tokenRec.Code, http.StatusBadRequest, tokenRec.Body.String())
	}
}

func TestBuiltinRefreshIssuesNewGatewayJWT(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "frank"}, nil
		},
	)

	verifier := "refresh-verifier-abcdefghijklmnopqrstuvwxyz0123"
	challenge := pkceChallenge(verifier)
	const state = "refresh-test-state"
	const redirectURI = "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	redirectURL, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := redirectURL.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("initial token: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
	}

	var tokenResp map[string]any
	_ = json.NewDecoder(tokenRec.Body).Decode(&tokenResp)
	firstAccessToken, _ := tokenResp["access_token"].(string)
	refreshToken, _ := tokenResp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("missing refresh_token in initial response")
	}

	// Use refresh token to obtain a new gateway JWT
	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}

	var refreshResp map[string]any
	_ = json.NewDecoder(refreshRec.Body).Decode(&refreshResp)
	newAccessToken, _ := refreshResp["access_token"].(string)
	if newAccessToken == "" {
		t.Fatal("refresh response missing access_token")
	}
	if newAccessToken == firstAccessToken {
		t.Error("refresh must issue a new access_token, not reuse the original")
	}
	if strings.Count(newAccessToken, ".") != 2 {
		t.Errorf("refreshed access_token is not a JWT: %q", newAccessToken)
	}
	if newRT, _ := refreshResp["refresh_token"].(string); newRT == "" {
		t.Error("refresh response missing new refresh_token")
	}
}

// runBuiltinFullFlow performs a full authorize→callback→token flow in builtin mode
// and returns the token response and the issued access_token.
func runBuiltinFullFlow(t *testing.T, h *Handler, subject string) (resp map[string]any, accessToken string) {
	t.Helper()
	verifier := "builtin-flow-verifier-abcdefghijklmnopqrstuvwxyz0"
	challenge := pkceChallenge(verifier)
	state := "flow-state-" + subject
	redirectURI := "http://localhost/cb"

	authReq := httptest.NewRequest(http.MethodGet,
		"/authorize?response_type=code&state="+state+"&redirect_uri="+url.QueryEscape(redirectURI)+
			"&code_challenge="+challenge+"&code_challenge_method=S256", nil)
	h.Authorize(httptest.NewRecorder(), authReq)

	cbReq := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+state, nil)
	cbRec := httptest.NewRecorder()
	h.Callback(cbRec, cbReq)
	if cbRec.Code != http.StatusFound {
		t.Fatalf("callback: got %d; body=%s", cbRec.Code, cbRec.Body.String())
	}
	redirectURL, _ := url.Parse(cbRec.Header().Get("Location"))
	internalCode := redirectURL.Query().Get("code")

	tokenBody := "grant_type=authorization_code" +
		"&redirect_uri=" + url.QueryEscape(redirectURI) +
		"&code=" + url.QueryEscape(internalCode) +
		"&code_verifier=" + url.QueryEscape(verifier)
	tokenReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(tokenBody))
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	tokenRec := httptest.NewRecorder()
	h.Token(tokenRec, tokenReq)
	if tokenRec.Code != http.StatusOK {
		t.Fatalf("token: got %d; body=%s", tokenRec.Code, tokenRec.Body.String())
	}
	_ = json.NewDecoder(tokenRec.Body).Decode(&resp)
	accessToken, _ = resp["access_token"].(string)
	return resp, accessToken
}

func TestBuiltinValidateTokenCacheMiss(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "zoe"}, nil
		},
	)

	_, accessToken := runBuiltinFullFlow(t, h, "zoe")

	// Create a fresh handler with the same key so the token store is empty (cache miss).
	h2 := newBuiltinTestHandlerWithKey(t, h.privateKey,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "zoe"}, nil
		},
	)

	sub, _, err := h2.ValidateToken(context.Background(), accessToken, "")
	if err != nil {
		t.Fatalf("ValidateToken on cache miss: %v", err)
	}
	if sub != "zoe" {
		t.Errorf("subject: got %q, want %q", sub, "zoe")
	}
}

func TestBuiltinValidateTokenExpiredJWT(t *testing.T) {
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "expired-user"}, nil
		},
	)

	// Generate an already-expired gateway JWT directly.
	expiredToken, err := generateExpiredGatewayToken(h.privateKey, "expired-user", "")
	if err != nil {
		t.Fatalf("generate expired token: %v", err)
	}

	_, _, err = h.ValidateToken(context.Background(), expiredToken, "")
	if err == nil {
		t.Error("expected error for expired JWT, got nil")
	}
}

func TestBuiltinValidateTokenAudienceStrict(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &provider.Mock{
		NameValue:     "builtin",
		ClientIDValue: "builtin-client-id",
		ScopesValue:   "read:user,user:email",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "gh-tok"}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "strict-user"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:             "http://localhost:8080",
		SessionTTL:          10 * time.Minute,
		CacheTTL:            5 * time.Minute,
		ExpiresIn:           90 * 24 * time.Hour,
		OIDCPrivateKey:      key,
		TokenAudienceStrict: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	_, accessToken := runBuiltinFullFlow(t, h, "strict-user")

	// ValidateToken with TokenAudienceStrict=true must still succeed for builtin
	// tokens even on cache miss (audience is taken from the JWT aud claim).
	sub, _, valErr := h.ValidateToken(context.Background(), accessToken, "")
	if valErr != nil {
		t.Fatalf("ValidateToken with TokenAudienceStrict: %v", valErr)
	}
	if sub != "strict-user" {
		t.Errorf("subject: got %q, want %q", sub, "strict-user")
	}
}

// newBuiltinTestHandlerWithKey is like newBuiltinTestHandler but uses a given RSA key.
func newBuiltinTestHandlerWithKey(t *testing.T, key *rsa.PrivateKey, ghExchange func(context.Context, string) (provider.TokenResponse, error), ghValidate func(context.Context, string) (provider.Identity, error)) *Handler {
	t.Helper()
	p := &provider.Mock{
		NameValue:        "builtin",
		ClientIDValue:    "builtin-client-id",
		ScopesValue:      "read:user,user:email",
		ExchangeCodeFunc: ghExchange,
		ValidateFunc:     ghValidate,
	}
	h, err := NewHandler(Config{
		BaseURL:        "http://localhost:8080",
		SessionTTL:     10 * time.Minute,
		CacheTTL:       5 * time.Minute,
		ExpiresIn:      90 * 24 * time.Hour,
		OIDCPrivateKey: key,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// generateExpiredGatewayToken creates a gateway-signed JWT with exp in the past.
func generateExpiredGatewayToken(key *rsa.PrivateKey, subject, audience string) (string, error) {
	header := map[string]string{"alg": "RS256", "typ": "JWT", "kid": "gateway-key-1"}
	headerBytes, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerBytes)

	now := time.Now().Unix()
	payload := map[string]any{
		"iss": "http://localhost:8080",
		"sub": subject,
		"aud": audience,
		"iat": now - 7200,
		"exp": now - 3600, // already expired
		"jti": "expired-jti",
	}
	payloadBytes, _ := json.Marshal(payload)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadBytes)

	signingInput := headerB64 + "." + payloadB64
	h := sha256.New()
	h.Write([]byte(signingInput))
	hashed := h.Sum(nil)
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed)
	if err != nil {
		return "", err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sigBytes), nil
}

func TestDeviceAuthorizeInvalidResource(t *testing.T) {
	h := newTestHandler(t)

	// Multiple resource params → resolveRequestedAudience error → invalid_target.
	r := httptest.NewRequest(http.MethodPost, "/device_authorization",
		strings.NewReader("resource=res-a&resource=res-b"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.DeviceAuthorize(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_target" {
		t.Errorf("error: got %v, want invalid_target", resp["error"])
	}
}

func TestTokenDeviceGrantMissingDeviceCode(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodPost, "/token",
		strings.NewReader("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] != "invalid_request" {
		t.Errorf("error: got %v, want invalid_request", resp["error"])
	}
}

func TestTokenDeviceGrantUnknownDeviceCode(t *testing.T) {
	h := newTestHandler(t)

	body := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code=nonexistent-code"
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_grant" {
		t.Errorf("error: got %v, want invalid_grant", resp["error"])
	}
}

func TestTokenDeviceGrantExpired(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(-time.Second) // already expired
	internalCode, err := h.store.CreateDevice("ABCD-EXPI", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "expired_token" {
		t.Errorf("error: got %v, want expired_token", resp["error"])
	}
}

func TestTokenDeviceGrantDenied(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("DENY-ABCD", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	h.store.DenyDevice(internalCode)

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "access_denied" {
		t.Errorf("error: got %v, want access_denied", resp["error"])
	}
}

func TestTokenDeviceGrantAlreadyConsumed(t *testing.T) {
	h := newTestHandler(t)

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, err := h.store.CreateDevice("CONS-ABCD", expiresAt, "mcp-gateway", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	h.store.ApproveDevice(internalCode, "tok", "repo", "alice", "", time.Time{})
	// Consume once — simulates first poll having already taken the token.
	h.store.ConsumeApprovedDevice(internalCode)

	// Second poll: session deleted → GetDevice returns false → invalid_grant.
	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", internalCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	h.Token(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	var resp map[string]any
	_ = json.NewDecoder(w.Body).Decode(&resp)
	if resp["error"] != "invalid_grant" {
		t.Errorf("error: got %v, want invalid_grant", resp["error"])
	}
}

func TestActivateSubmitEmptyCode(t *testing.T) {
	h := newTestHandler(t)

	r := httptest.NewRequest(http.MethodPost, "/activate",
		strings.NewReader("user_code="))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ActivateSubmit(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

func TestDeviceCallbackBadStateFormat(t *testing.T) {
	h := newTestHandler(t)

	// A state that passes HasSession but has no "device:" prefix.
	h.store.SaveSession("plain-state-no-prefix", "http://localhost:8080/device_callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/device_callback?code=abc&state=plain-state-no-prefix", nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
	if !strings.Contains(w.Body.String(), "invalid state format") {
		t.Errorf("body: want 'invalid state format', got %q", w.Body.String())
	}
}

func TestDeviceCallbackExchangeCodeError(t *testing.T) {
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, fmt.Errorf("upstream exchange failed")
		},
	}
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, _ := h.store.CreateDevice("XCBG-1234", expiresAt, "mcp", "")
	state := generateDeviceState(internalCode)
	h.store.SaveSession(state, "http://localhost:8080/device_callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/device_callback?code=abc&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", w.Code)
	}
}

func TestDeviceCallbackValidateTokenError(t *testing.T) {
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "tok"}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{}, fmt.Errorf("cannot validate")
		},
	}
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	expiresAt := time.Now().Add(15 * time.Minute)
	internalCode, _ := h.store.CreateDevice("XCBG-5678", expiresAt, "mcp", "")
	state := generateDeviceState(internalCode)
	h.store.SaveSession(state, "http://localhost:8080/device_callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/device_callback?code=abc&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadGateway {
		t.Fatalf("status: got %d, want 502", w.Code)
	}
}

// TestCallbackDeviceFlowFallback verifies the fix for the case where GitHub
// always redirects to /callback (because AuthorizeURL sets redirect_uri=/callback)
// even during Device Flow. The Callback handler must detect device state and call
// ApproveDevice directly instead of forwarding the code to /device_callback, which
// would cause a bad_verification_code error on the second ExchangeCode attempt.
func TestCallbackDeviceFlowFallback(t *testing.T) {
	exchangeCalled := 0
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, code string) (provider.TokenResponse, error) {
			exchangeCalled++
			return provider.TokenResponse{AccessToken: "ghu_tok", Scopes: []string{"repo"}}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// Set up a device session as /activate would.
	deviceCode, err := h.store.CreateDevice("ABCD-1234", time.Now().Add(10*time.Minute), "mcp", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	state := generateDeviceState(deviceCode)
	h.store.SaveSession(state, "http://localhost:8080/device_callback", "", "mcp", "", "")

	// Simulate GitHub redirecting to /callback with a device state (not /device_callback).
	r := httptest.NewRequest(http.MethodGet, "/callback?code=github-code-abc&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "Device activated") {
		t.Errorf("body does not contain 'Device activated': %s", w.Body.String())
	}
	// ExchangeCode must be called exactly once (in Callback); DeviceCallback must NOT be called.
	if exchangeCalled != 1 {
		t.Errorf("ExchangeCode called %d times, want 1", exchangeCalled)
	}
	// Device session must be approved.
	sess, ok := h.store.GetDevice(deviceCode)
	if !ok {
		t.Fatal("GetDevice: session not found")
	}
	if sess.AccessToken != "ghu_tok" {
		t.Errorf("device session token: got %q want %q", sess.AccessToken, "ghu_tok")
	}
}

// TestCallbackDeviceStateNoMatchFallsToNormalFlow verifies that a state value
// prefixed "device:" falls through to the normal Authorization Code Flow when no
// live device session exists for the embedded code. This guards against legitimate
// opaque state values (e.g. from an MCP client) being misidentified as device flow.
func TestCallbackDeviceStateNoMatchFallsToNormalFlow(t *testing.T) {
	exchangeCalled := 0
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			exchangeCalled++
			return provider.TokenResponse{AccessToken: "ghu_tok", Scopes: []string{"repo"}}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// State looks like a device state but has no matching device session in the store.
	state := "device:no-such-device-code"
	h.store.SaveSession(state, "http://localhost:8080/callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)

	// Normal flow: CompleteCallback → redirect to redirect_uri?code=...
	if w.Code != http.StatusFound {
		t.Fatalf("status: got %d want 302; body: %s", w.Code, w.Body.String())
	}
	if exchangeCalled != 1 {
		t.Errorf("ExchangeCode called %d times, want 1", exchangeCalled)
	}
}

// TestCallbackDeviceFlowFallbackPersistsProviderRefresh verifies that the Callback
// handler forwards provider refresh metadata (refresh token + access expiry) to
// ApproveDevice so that the rotation path in tokenDeviceGrant has the data it needs.
func TestCallbackDeviceFlowFallbackPersistsProviderRefresh(t *testing.T) {
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{
				AccessToken:          "ghu_tok",
				RefreshToken:         "ghr_refresh",
				AccessTokenExpiresIn: 8 * time.Hour,
				Scopes:               []string{"repo"},
			}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	deviceCode, err := h.store.CreateDevice("EFGH-5678", time.Now().Add(10*time.Minute), "mcp", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	state := generateDeviceState(deviceCode)
	h.store.SaveSession(state, "http://localhost:8080/device_callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/callback?code=gh-code&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.Callback(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status: got %d want 200; body: %s", w.Code, w.Body.String())
	}
	sess, ok := h.store.GetDevice(deviceCode)
	if !ok {
		t.Fatal("GetDevice: session not found after Callback")
	}
	if sess.ProviderRefreshToken != "ghr_refresh" {
		t.Errorf("ProviderRefreshToken: got %q want %q", sess.ProviderRefreshToken, "ghr_refresh")
	}
	if sess.ProviderAccessExpiry.IsZero() {
		t.Error("ProviderAccessExpiry should not be zero")
	}
}

// TestTokenDeviceGrantPersistsProviderRefresh verifies that tokenDeviceGrant calls
// persistProviderRefresh after CacheToken so the rotation path (#140) fires
// correctly for device-flow-issued ghu_ tokens.
func TestTokenDeviceGrantPersistsProviderRefresh(t *testing.T) {
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "ghu_provider_tok"}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		GitHubRefreshEnabled: true,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	expiry := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	deviceCode, err := h.store.CreateDevice("IJKL-9999", time.Now().Add(10*time.Minute), "mcp", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if !h.store.ApproveDevice(deviceCode, "ghu_provider_tok", "repo", "alice", "ghr_stored", expiry) {
		t.Fatal("ApproveDevice failed")
	}

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", deviceCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("token exchange: got %d want 200; body: %s", w.Code, w.Body.String())
	}
	_, rec, ok := h.store.LatestBySubject("alice")
	if !ok {
		t.Fatal("LatestBySubject: no record found after token exchange")
	}
	if rec.ProviderRefreshToken != "ghr_stored" {
		t.Errorf("ProviderRefreshToken: got %q want %q", rec.ProviderRefreshToken, "ghr_stored")
	}
	if rec.ProviderAccessExpiry.IsZero() {
		t.Error("ProviderAccessExpiry should not be zero after token exchange")
	}
}

func TestDeviceCallbackApproveDeviceFails(t *testing.T) {
	p := &provider.Mock{
		ClientIDValue: "test-client-id",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: "tok"}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Provider: "mock", Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// State encodes a device internalCode that does not exist in the store.
	state := generateDeviceState("nonexistent-device-code")
	h.store.SaveSession(state, "http://localhost:8080/device_callback", "", "mcp", "", "")

	r := httptest.NewRequest(http.MethodGet, "/device_callback?code=abc&state="+url.QueryEscape(state), nil)
	w := httptest.NewRecorder()
	h.DeviceCallback(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status: got %d, want 400", w.Code)
	}
}

// ── scottlz0310/mcp-gateway#188 regression tests ───────────────────────────
//
// These verify that builtin mode retains the GitHub provider access token
// (indexed under the gateway JWT) across the authorization-code flow, the
// device flow, and refresh_token rotation, and that ValidateToken never
// leaks a raw provider token through the non-builtin rotation path.

// TestBuiltinTokenAuthCodePersistsProviderAccessToken verifies that
// tokenAuthCode's builtin branch records the GitHub access token obtained
// during ExchangeCode, indexed under the issued gateway JWT.
func TestBuiltinTokenAuthCodePersistsProviderAccessToken(t *testing.T) {
	const ghAccessToken = "gho_authcode_provider_tok"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "grace"}, nil
		},
	)

	_, jwt := runBuiltinFullFlow(t, h, "grace")
	if jwt == "" {
		t.Fatal("runBuiltinFullFlow: empty access_token in token response")
	}

	rec, ok := h.store.LookupToken(jwt)
	if !ok {
		t.Fatal("LookupToken: expected cache hit for issued JWT")
	}
	if rec.ProviderAccessToken != ghAccessToken {
		t.Errorf("ProviderAccessToken: got %q, want %q", rec.ProviderAccessToken, ghAccessToken)
	}
}

// TestBuiltinDeviceGrantPersistsProviderAccessToken verifies that
// tokenDeviceGrant's builtin branch records the GitHub access token approved
// via the device flow, indexed under the issued gateway JWT (not under the
// GitHub token itself, which is never cached in builtin mode).
func TestBuiltinDeviceGrantPersistsProviderAccessToken(t *testing.T) {
	const ghAccessToken = "gho_device_provider_tok"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "heidi"}, nil
		},
	)

	deviceCode, err := h.store.CreateDevice("DEVI-0001", time.Now().Add(10*time.Minute), "mcp-gateway", "")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if !h.store.ApproveDevice(deviceCode, ghAccessToken, "read:user", "heidi", "", time.Time{}) {
		t.Fatal("ApproveDevice failed")
	}

	body := fmt.Sprintf("grant_type=urn:ietf%%3Aparams%%3Aoauth%%3Agrant-type%%3Adevice_code&device_code=%s", deviceCode)
	r := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.Token(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("token exchange: got %d want 200; body: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	jwt, _ := resp["access_token"].(string)
	if jwt == "" {
		t.Fatal("device token response: empty access_token")
	}
	if jwt == ghAccessToken {
		t.Fatal("device token response leaked the raw GitHub access token instead of a gateway JWT")
	}

	rec, ok := h.store.LookupToken(jwt)
	if !ok {
		t.Fatal("LookupToken: expected cache hit for issued JWT")
	}
	if rec.ProviderAccessToken != ghAccessToken {
		t.Errorf("ProviderAccessToken: got %q, want %q", rec.ProviderAccessToken, ghAccessToken)
	}
}

// TestBuiltinTokenRefreshCarriesForwardProviderAccessToken verifies that
// tokenRefresh's builtin branch carries the provider access token forward to
// the newly-issued gateway JWT.
func TestBuiltinTokenRefreshCarriesForwardProviderAccessToken(t *testing.T) {
	const ghAccessToken = "gho_refresh_provider_tok"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "ivan"}, nil
		},
	)

	tokenResp, firstJWT := runBuiltinFullFlow(t, h, "ivan")
	refreshToken, _ := tokenResp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("missing refresh_token in initial response")
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp map[string]any
	_ = json.NewDecoder(refreshRec.Body).Decode(&refreshResp)
	newJWT, _ := refreshResp["access_token"].(string)
	if newJWT == "" || newJWT == firstJWT {
		t.Fatalf("refresh must issue a new JWT: got %q (first was %q)", newJWT, firstJWT)
	}

	rec, ok := h.store.LookupToken(newJWT)
	if !ok {
		t.Fatal("LookupToken: expected cache hit for refreshed JWT")
	}
	if rec.ProviderAccessToken != ghAccessToken {
		t.Errorf("ProviderAccessToken after refresh: got %q, want %q", rec.ProviderAccessToken, ghAccessToken)
	}
}

// TestBuiltinTokenRefreshCarriesForwardAfterOldRecordSwept is the direct
// regression test for the refresh-token grace-period gap identified during
// the #188 investigation: refresh tokens outlive the access-token TokenStore
// entry by design (30-day grace period beyond the access token TTL), so by
// the time a client refreshes, the old JWT's TokenRecord may already be gone.
// The provider access token must still be recoverable via the refresh token
// itself, not via the old JWT's (possibly-swept) record.
func TestBuiltinTokenRefreshCarriesForwardAfterOldRecordSwept(t *testing.T) {
	const ghAccessToken = "gho_swept_provider_tok"
	h := newBuiltinTestHandler(t,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "judy"}, nil
		},
	)

	tokenResp, firstJWT := runBuiltinFullFlow(t, h, "judy")
	refreshToken, _ := tokenResp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("missing refresh_token in initial response")
	}

	// Simulate the old JWT's TokenStore entry having already been swept
	// (e.g. it hit its CacheTTL before the client got around to refreshing).
	h.InvalidateCachedToken(firstJWT)
	if _, ok := h.store.LookupToken(firstJWT); ok {
		t.Fatal("setup: expected old JWT to be evicted from the token store")
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp map[string]any
	_ = json.NewDecoder(refreshRec.Body).Decode(&refreshResp)
	newJWT, _ := refreshResp["access_token"].(string)
	if newJWT == "" {
		t.Fatal("refresh response missing access_token")
	}

	rec, ok := h.store.LookupToken(newJWT)
	if !ok {
		t.Fatal("LookupToken: expected cache hit for refreshed JWT")
	}
	if rec.ProviderAccessToken != ghAccessToken {
		t.Errorf("ProviderAccessToken recovered via refresh token after old record sweep: got %q, want %q",
			rec.ProviderAccessToken, ghAccessToken)
	}
}

// TestValidateToken_BuiltinModeDoesNotRotateOnCacheHit is the security
// regression test for the ValidateToken cache-hit guard: even if a builtin
// JWT's TokenRecord somehow carries GitHub-style rotation metadata
// (ProviderRefreshToken/ProviderAccessExpiry), ValidateToken must never
// invoke the non-builtin rotation path for it, which would otherwise return
// a raw GitHub access token as rotatedToken — leaking it via ContextKeyToken
// to any route that forwards the bearer, not just upstream_provider_token
// routes. See scottlz0310/mcp-gateway#188.
func TestValidateToken_BuiltinModeDoesNotRotateOnCacheHit(t *testing.T) {
	var refreshCalled bool
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &provider.Mock{
		NameValue:     "builtin",
		ClientIDValue: "builtin-client-id",
		ScopesValue:   "read:user,user:email",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			refreshCalled = true
			return provider.TokenResponse{AccessToken: "gho_leaked_via_rotation"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		OIDCPrivateKey:       key,
		GitHubRefreshEnabled: true,
		GitHubRefreshLeeway:  time.Hour, // wide leeway so any expiry in the past triggers rotation
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	jwt, _, err := h.generateGatewayAccessToken("kevin", "http://localhost:8080")
	if err != nil {
		t.Fatalf("generateGatewayAccessToken: %v", err)
	}
	h.store.CacheToken(jwt, "kevin", "http://localhost:8080")
	// Force rotation preconditions to be satisfied: known subject, refresh
	// metadata present, expiry already within (in fact past) the leeway window.
	h.store.RecordProviderRefresh(jwt, "gh-refresh-should-not-be-used", time.Now().Add(-time.Minute))

	sub, rotated, err := h.ValidateToken(context.Background(), jwt, "")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if sub != "kevin" {
		t.Errorf("subject: got %q, want %q", sub, "kevin")
	}
	if rotated != "" {
		t.Fatalf("regression: ValidateToken returned a rotated token in builtin mode: %q (must be empty)", rotated)
	}
	if refreshCalled {
		t.Fatal("regression: provider.RefreshToken was invoked for a builtin-mode JWT on cache hit")
	}
}
