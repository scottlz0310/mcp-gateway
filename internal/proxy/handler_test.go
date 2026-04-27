package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// testValidator is a stub TokenValidator for integration-level tests.
type testValidator struct{ login string }

func (v *testValidator) ValidateToken(_ context.Context, _ string) (string, error) {
	return v.login, nil
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
	h := NewHandler(u, &mockInvalidator{})

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
		xff      string
		realIP   string
		authUser string
		legacy   string
		fwdHost  string
		fwdProto string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.xff = r.Header.Get("X-Forwarded-For")
		got.realIP = r.Header.Get("X-Real-Ip")
		got.authUser = r.Header.Get("X-Authenticated-User")
		got.legacy = r.Header.Get("X-GitHub-Login")
		got.fwdHost = r.Header.Get("X-Forwarded-Host")
		got.fwdProto = r.Header.Get("X-Forwarded-Proto")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{})

	r := requestWithContext("bob", "tok")
	r.Header.Set("X-Forwarded-For", "1.2.3.4")
	r.Header.Set("X-Real-Ip", "1.2.3.4")
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
	h := NewHandler(u, &mockInvalidator{})

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
	h := NewHandler(u, inv)

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
	h := NewHandler(u, &mockInvalidator{})

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
	h := NewHandler(u, nil)

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
	chain := middleware.Auth(validator)(NewHandler(u, &mockInvalidator{}))

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
