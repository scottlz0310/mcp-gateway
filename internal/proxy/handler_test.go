package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

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

func requestWithContext(login, token string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/mcp/test", nil)
	ctx := context.WithValue(r.Context(), middleware.ContextKeyLogin, login)
	ctx = context.WithValue(ctx, middleware.ContextKeyToken, token)
	return r.WithContext(ctx)
}

func TestProxyInjectsXGitHubLogin(t *testing.T) {
	var gotLogin string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotLogin = r.Header.Get("X-GitHub-Login")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{})

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "tok"))

	if gotLogin != "alice" {
		t.Errorf("X-GitHub-Login: got %q, want %q", gotLogin, "alice")
	}
}

func TestProxyStripsClientSpoofableHeaders(t *testing.T) {
	var got struct {
		xff      string
		realIP   string
		login    string
		fwdHost  string
		fwdProto string
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.xff = r.Header.Get("X-Forwarded-For")
		got.realIP = r.Header.Get("X-Real-Ip")
		got.login = r.Header.Get("X-GitHub-Login")
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
	if got.login != "bob" {
		t.Errorf("X-GitHub-Login spoofed: got %q, want %q", got.login, "bob")
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

func TestProxyNilInvalidatorDoesNotPanicOn401(t *testing.T) {
	upstream := upstreamWithStatus(http.StatusUnauthorized)
	defer upstream.Close()

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, nil)

	w := httptest.NewRecorder()
	// Must not panic.
	h.ServeHTTP(w, requestWithContext("eve", "tok"))
}
