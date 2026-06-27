package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// testValidator is a stub TokenValidator for integration-level tests.
type testValidator struct {
	login        string
	rotatedToken string
}

func (v *testValidator) ValidateToken(_ context.Context, _, _ string) (string, string, error) {
	return v.login, v.rotatedToken, nil
}

type mockInvalidator struct {
	tokens []string
}

func (m *mockInvalidator) InvalidateCachedToken(token string) {
	m.tokens = append(m.tokens, token)
}

func upstreamWithStatus(code int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(code)
	}))
}

func requestWithContext(identity, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/mcp/test", nil)
	ctx := context.WithValue(r.Context(), middleware.ContextKeyIdentity, identity)
	ctx = context.WithValue(ctx, middleware.ContextKeyToken, token)
	return r.WithContext(ctx)
}

func TestProxyInjectsIdentityHeaders(t *testing.T) {
	var gotAuthUser, gotLegacyLogin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthUser = r.Header.Get("X-Authenticated-User")
		gotLegacyLogin = r.Header.Get("X-GitHub-Login")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "tok"))

	if gotAuthUser != "alice" {
		t.Errorf("X-Authenticated-User: got %q, want %q", gotAuthUser, "alice")
	}
	if gotLegacyLogin != "alice" {
		t.Errorf("X-GitHub-Login (legacy): got %q, want %q", gotLegacyLogin, "alice")
	}
}

func TestProxyStripsClientSpoofableHeaders(t *testing.T) {
	var got struct {
		xff       string
		realIP    string
		forwarded string
		authUser  string
		legacy    string
		fwdHost   string
		fwdProto  string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.xff = r.Header.Get("X-Forwarded-For")
		got.realIP = r.Header.Get("X-Real-Ip")
		got.forwarded = r.Header.Get("Forwarded")
		got.authUser = r.Header.Get("X-Authenticated-User")
		got.legacy = r.Header.Get("X-GitHub-Login")
		got.fwdHost = r.Header.Get("X-Forwarded-Host")
		got.fwdProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	r := requestWithContext("bob", "tok")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-Ip", "1.2.3.4")
	r.Header.Set("Forwarded", "for=1.2.3.4;proto=https;host=evil.example.com")
	r.Header.Set("X-Authenticated-User", "evil-spoof")
	r.Header.Set("X-GitHub-Login", "evil-spoof")
	r.Header.Set("X-Forwarded-Host", "evil.example.com")
	r.Header.Set("X-Forwarded-Proto", "https")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if got.xff != "" {
		t.Errorf("X-Forwarded-For not stripped: %q", got.xff)
	}
	if got.realIP != "" {
		t.Errorf("X-Real-Ip not stripped: %q", got.realIP)
	}
	if got.forwarded != "" {
		t.Errorf("Forwarded not stripped: %q", got.forwarded)
	}
	if got.authUser != "bob" {
		t.Errorf("X-Authenticated-User spoofed: got %q, want %q", got.authUser, "bob")
	}
	if got.legacy != "bob" {
		t.Errorf("X-GitHub-Login spoofed: got %q, want %q", got.legacy, "bob")
	}
	if got.fwdHost != "" {
		t.Errorf("X-Forwarded-Host not stripped: %q", got.fwdHost)
	}
	if got.fwdProto != "" {
		t.Errorf("X-Forwarded-Proto not stripped: %q", got.fwdProto)
	}
}

func TestProxyNormalizesAuthorization(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	r := requestWithContext("carol", "ctx-token")
	r.Header.Set("Authorization", "Bearer client-supplied-token")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotAuth != "Bearer ctx-token" {
		t.Errorf("Authorization: got %q, want %q", gotAuth, "Bearer ctx-token")
	}
}

func TestProxyInvalidatesCacheOn401(t *testing.T) {
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	inv := &mockInvalidator{}
	h := NewHandler(u, inv, "", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("dave", "secret-token"))

	if len(inv.tokens) != 1 || inv.tokens[0] != "secret-token" {
		t.Errorf("invalidated tokens: %v", inv.tokens)
	}
}

func TestProxySanitizesHeaderInjectionCharacters(t *testing.T) {
	var gotAuthUser string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthUser = r.Header.Get("X-Authenticated-User")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice\r\nevil: injected", "tok"))

	if strings.Contains(gotAuthUser, "\r") || strings.Contains(gotAuthUser, "\n") {
		t.Errorf("X-Authenticated-User contains CR/LF: %q", gotAuthUser)
	}
}

func TestProxyNilInvalidatorDoesNotPanicOn401(t *testing.T) {
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, nil, "", "", nil)

	w := httptest.NewRecorder()
	// Must not panic.
	h.ServeHTTP(w, requestWithContext("eve", "tok"))
}

// TestMiddlewareToProxyInjectsIdentityHeaders verifies the complete pipeline:
// Auth middleware → proxy handler → upstream, confirming that both
// X-Authenticated-User and X-GitHub-Login reach the upstream service
// (e.g. github-mcp, copilot-review-mcp) on every proxied request.
func TestMiddlewareToProxyInjectsIdentityHeaders(t *testing.T) {
	var (
		gotAuthUser    string
		gotLegacyLogin string
		gotAuth        string
	)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthUser = r.Header.Get("X-Authenticated-User")
		gotLegacyLogin = r.Header.Get("X-GitHub-Login")
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	validator := &testValidator{login: "octocat"}
	chain := middleware.Auth(validator)(NewHandler(u, &mockInvalidator{}, "", "", nil))

	r := httptest.NewRequest(http.MethodGet, "/mcp/test", nil)
	r.Header.Set("Authorization", "Bearer real-github-token")
	w := httptest.NewRecorder()
	chain.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from upstream, got %d", w.Code)
	}
	if gotAuthUser != "octocat" {
		t.Errorf("X-Authenticated-User: got %q, want %q", gotAuthUser, "octocat")
	}
	if gotLegacyLogin != "octocat" {
		t.Errorf("X-GitHub-Login (legacy): got %q, want %q", gotLegacyLogin, "octocat")
	}
	if gotAuth != "Bearer real-github-token" {
		t.Errorf("Authorization: got %q, want %q", gotAuth, "Bearer real-github-token")
	}
}

func TestProxyUpstreamBearerEnvInjectsToken(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_TEST_TOKEN", "env-api-token")
	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "UPSTREAM_TEST_TOKEN", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "client-oauth-token"))

	if gotAuth != "Bearer env-api-token" {
		t.Errorf("Authorization: got %q, want %q", gotAuth, "Bearer env-api-token")
	}
}

func TestProxyUpstreamBearerEnvStripsClientAuth(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	t.Setenv("UPSTREAM_TEST_TOKEN2", "real-env-token")
	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "UPSTREAM_TEST_TOKEN2", "", nil)

	req := requestWithContext("bob", "client-token")
	req.Header.Set("Authorization", "Bearer client-supplied-auth")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if gotAuth != "Bearer real-env-token" {
		t.Errorf("Authorization: got %q, want %q (client token must not leak through)", gotAuth, "Bearer real-env-token")
	}
}

func TestProxyUpstreamBearerEnvDoesNotInvalidateOn401(t *testing.T) {
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	t.Setenv("UPSTREAM_TEST_TOKEN3", "some-api-token")
	u, _ := url.Parse(upstream.URL)
	inv := &mockInvalidator{}
	h := NewHandler(u, inv, "UPSTREAM_TEST_TOKEN3", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("carol", "client-oauth-token"))

	if len(inv.tokens) != 0 {
		t.Errorf("expected no invalidated tokens for upstream-credential route, got %v", inv.tokens)
	}
}

func TestProxyStripsRoutingPrefix(t *testing.T) {
	tests := []struct {
		name        string
		prefix      string
		requestPath string
		wantPath    string
	}{
		{
			name:        "strips prefix from path",
			prefix:      "/mcp/github",
			requestPath: "/mcp/github/sse",
			wantPath:    "/sse",
		},
		{
			name:        "strips prefix, root becomes slash",
			prefix:      "/mcp/github",
			requestPath: "/mcp/github",
			wantPath:    "/",
		},
		{
			name:        "no prefix (empty), path unchanged",
			prefix:      "",
			requestPath: "/mcp/github/sse",
			wantPath:    "/mcp/github/sse",
		},
		{
			name:        "root prefix, path unchanged",
			prefix:      "/",
			requestPath: "/mcp/github/sse",
			wantPath:    "/mcp/github/sse",
		},
		{
			name:        "path does not start with prefix, unchanged",
			prefix:      "/mcp/github",
			requestPath: "/other/path",
			wantPath:    "/other/path",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			u, _ := url.Parse(upstream.URL)
			h := NewHandler(u, &mockInvalidator{}, "", tc.prefix, nil)

			r := httptest.NewRequest(http.MethodGet, tc.requestPath, nil)
			ctx := context.WithValue(r.Context(), middleware.ContextKeyIdentity, "alice")
			ctx = context.WithValue(ctx, middleware.ContextKeyToken, "tok")
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if gotPath != tc.wantPath {
				t.Errorf("upstream path: got %q, want %q", gotPath, tc.wantPath)
			}
		})
	}
}

// TestProxyStripsRoutingPrefixWithUpstreamBasePath verifies that prefix stripping
// happens before SetURL so that an upstream with a base path (e.g.
// https://mcp.cloudflare.com/mcp) receives prefix-stripped_path appended to its
// own base, not the full gateway path.
func TestProxyStripsRoutingPrefixWithUpstreamBasePath(t *testing.T) {
	tests := []struct {
		name          string
		prefix        string
		upstreamBase  string // path suffix added to httptest server URL
		requestTarget string
		wantPath      string
		wantRawPath   string
		wantRawQuery  string
	}{
		{
			name:          "upstream with base path: prefix stripped then base prepended",
			prefix:        "/mcp/cloudflare",
			upstreamBase:  "/mcp",
			requestTarget: "/mcp/cloudflare/sse",
			wantPath:      "/mcp/sse",
		},
		{
			name:          "upstream with base path: exact prefix preserves base path",
			prefix:        "/mcp/cloudflare",
			upstreamBase:  "/mcp",
			requestTarget: "/mcp/cloudflare",
			wantPath:      "/mcp",
		},
		{
			name:          "upstream without base path: exact prefix becomes root",
			prefix:        "/mcp/github",
			requestTarget: "/mcp/github",
			wantPath:      "/",
		},
		{
			name:          "exact prefix preserves upstream raw path and request query",
			prefix:        "/mcp/cloudflare",
			upstreamBase:  "/mcp%2Fv1",
			requestTarget: "/mcp/cloudflare?session=abc",
			wantPath:      "/mcp/v1",
			wantRawPath:   "/mcp%2Fv1",
			wantRawQuery:  "session=abc",
		},
		{
			name:          "upstream with base path: no prefix leaves path intact",
			prefix:        "",
			upstreamBase:  "/mcp",
			requestTarget: "/mcp/cloudflare/sse",
			wantPath:      "/mcp/mcp/cloudflare/sse",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var gotPath, gotRawPath, gotRawQuery string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotPath = r.URL.Path
				gotRawPath = r.URL.RawPath
				gotRawQuery = r.URL.RawQuery
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			u, _ := url.Parse(upstream.URL + tc.upstreamBase)
			h := NewHandler(u, &mockInvalidator{}, "", tc.prefix, nil)

			r := httptest.NewRequest(http.MethodGet, tc.requestTarget, nil)
			ctx := context.WithValue(r.Context(), middleware.ContextKeyIdentity, "alice")
			ctx = context.WithValue(ctx, middleware.ContextKeyToken, "tok")
			r = r.WithContext(ctx)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)

			if gotPath != tc.wantPath {
				t.Errorf("upstream path: got %q, want %q", gotPath, tc.wantPath)
			}
			if gotRawPath != tc.wantRawPath {
				t.Errorf("upstream raw path: got %q, want %q", gotRawPath, tc.wantRawPath)
			}
			if gotRawQuery != tc.wantRawQuery {
				t.Errorf("upstream raw query: got %q, want %q", gotRawQuery, tc.wantRawQuery)
			}
		})
	}
}

// TestProxyStripsRoutingPrefixRawPath verifies the RawPath branch: when the
// request URL contains percent-encoded characters, both Path and RawPath are
// stripped consistently so the upstream receives an aligned pair.
func TestProxyStripsRoutingPrefixRawPath(t *testing.T) {
	var gotPath, gotRawPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotRawPath = r.URL.RawPath
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "/mcp/test", nil)

	// %40 encodes '@': Path = /mcp/test/file@name, RawPath = /mcp/test/file%40name.
	r := httptest.NewRequest(http.MethodGet, "/mcp/test/file%40name", nil)
	ctx := context.WithValue(r.Context(), middleware.ContextKeyIdentity, "alice")
	ctx = context.WithValue(ctx, middleware.ContextKeyToken, "tok")
	r = r.WithContext(ctx)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotPath != "/file@name" {
		t.Errorf("upstream Path: got %q, want %q", gotPath, "/file@name")
	}
	if gotRawPath != "/file%40name" {
		t.Errorf("upstream RawPath: got %q, want %q", gotRawPath, "/file%40name")
	}
}

// TestProxyTransparentsMcpSessionIdRequest verifies that Mcp-Session-Id sent
// by the client is forwarded to the upstream unchanged. Go's HTTP stack
// canonicalizes header names (textproto.CanonicalMIMEHeaderKey), so casing
// variants are covered by standard net/http handling.
func TestProxyTransparentsMcpSessionIdRequest(t *testing.T) {
	var gotSessionID string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSessionID = r.Header.Get("Mcp-Session-Id")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	r := requestWithContext("alice", "tok")
	r.Header.Set("Mcp-Session-Id", "test-session-abc123")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotSessionID != "test-session-abc123" {
		t.Errorf("Mcp-Session-Id: got %q, want %q", gotSessionID, "test-session-abc123")
	}
}

// TestProxyTransparentsMcpSessionIdResponse verifies that Mcp-Session-Id
// returned by the upstream (e.g. in response to initialize) is forwarded to
// the client unchanged.
func TestProxyTransparentsMcpSessionIdResponse(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Mcp-Session-Id", "upstream-session-xyz789")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil)

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "tok"))

	if got := w.Header().Get("Mcp-Session-Id"); got != "upstream-session-xyz789" {
		t.Errorf("Mcp-Session-Id: got %q, want %q", got, "upstream-session-xyz789")
	}
}

func TestProxyUpstreamOAuthInjectsToken(t *testing.T) {
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("alice@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "upstream-access-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
	})

	r := requestWithContext("alice@example.com", "gateway-client-token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotAuth != "Bearer upstream-access-token" {
		t.Errorf("Authorization: got %q, want %q", gotAuth, "Bearer upstream-access-token")
	}
}

func TestProxyUpstreamOAuthDeletesTokenOn401(t *testing.T) {
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("bob@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "stale-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("bob@example.com", "gateway-client-token"))

	if _, ok := tokenStore.Lookup("bob@example.com", "myroute"); ok {
		t.Error("expected upstream token to be deleted after upstream 401")
	}
}

func TestProxyUpstreamOAuthDoesNotInvalidateGatewayTokenOn401(t *testing.T) {
	// When upstream_oauth is set and upstream returns 401, the gateway
	// client token cache must NOT be invalidated (the 401 is the upstream AS
	// rejecting our per-user token, not the gateway session token).
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("carol@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "upstream-tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	u, _ := url.Parse(upstream.URL)
	inv := &mockInvalidator{}
	h := NewHandler(u, inv, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("carol@example.com", "gateway-client-token"))

	if len(inv.tokens) != 0 {
		t.Errorf("expected no gateway token invalidation for upstream_oauth route, got %v", inv.tokens)
	}
}

// deleteErrStore wraps UpstreamTokenStore and returns a fixed error from Delete.
type deleteErrStore struct {
	inner     auth.UpstreamTokenStore
	deleteErr error
}

func (s *deleteErrStore) Save(subject, routeName string, rec auth.UpstreamTokenRecord) error {
	return s.inner.Save(subject, routeName, rec)
}
func (s *deleteErrStore) Lookup(subject, routeName string) (auth.UpstreamTokenRecord, bool) {
	return s.inner.Lookup(subject, routeName)
}
func (s *deleteErrStore) LookupForRefresh(subject, routeName string) (auth.UpstreamTokenRecord, bool) {
	return s.inner.LookupForRefresh(subject, routeName)
}
func (s *deleteErrStore) Delete(_, _ string) error { return s.deleteErr }
func (s *deleteErrStore) Sweep() error             { return s.inner.Sweep() }

func TestProxyUpstreamOAuthNoSubjectOn401(t *testing.T) {
	// subject が空（middleware なし）の場合 Delete は呼ばれず 401 がそのまま返る。
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
	})

	// request without identity in context
	req := httptest.NewRequest(http.MethodGet, "/mcp/myroute/sse", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestProxyUpstreamOAuthDeleteErrorOn401(t *testing.T) {
	// Delete が失敗した場合も 401 がそのまま返る（panic しない）。
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	inner := auth.NewMemUpstreamTokenStore()
	_ = inner.Save("dave@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	})
	tokenStore := &deleteErrStore{inner: inner, deleteErr: fmt.Errorf("flush error")}

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
	})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("dave@example.com", "gateway-client-token"))

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	// token must remain in store (Delete failed)
	if _, ok := inner.Lookup("dave@example.com", "myroute"); !ok {
		t.Error("token should remain when Delete fails")
	}
}
