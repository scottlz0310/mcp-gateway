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
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/user") {
			_, _ = fmt.Fprint(w, `{"login":"octocat","name":"The Octocat"}`)
			return
		}
		_, _ = fmt.Fprint(w, `{"access_token":"gha_success_token","scope":"repo,user","token_type":"bearer"}`)
	}))
	defer ghServer.Close()

	originalTransport := githubClient.Transport
	defer func() { githubClient.Transport = originalTransport }()
	githubClient.Transport = rewriteHostTransport{target: ghServer.URL, inner: ghServer.Client().Transport}

	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		UserAPI:      ghServer.URL + "/user",
		TokenURL:     ghServer.URL + "/login/oauth/access_token",
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
				// dropping it would force a provider round-trip — possibly a
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
		name              string
		refreshFunc       func(ctx context.Context, rt string) (provider.TokenResponse, error)
		wantMetadataKept  bool // true means metadata must remain intact for next retry
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
// another rotation (using the rotated refresh token) — i.e. the original
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
	h.store.SaveSession("state-oidc", "http://localhost/cb", "", "http://localhost:8080")
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

