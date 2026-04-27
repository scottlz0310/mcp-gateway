package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// mockValidator implements TokenValidator for testing.
type mockValidator struct {
	login string
	err   error
}

func (m *mockValidator) ValidateToken(_ context.Context, _ string) (string, error) {
	return m.login, m.err
}

// upstreamError satisfies the upstreamErrorer interface.
type upstreamError struct{ msg string }

func (e *upstreamError) Error() string         { return e.msg }
func (e *upstreamError) IsUpstreamError() bool { return true }

func okHandler(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

func TestAuthMissingToken(t *testing.T) {
	h := Auth(&mockValidator{login: "alice"})(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	assertJSONError(t, w, "missing_token")
	assertWWWAuthenticate(t, w)
}

func TestAuthInvalidToken(t *testing.T) {
	h := Auth(&mockValidator{err: fmt.Errorf("bad token")})(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	assertJSONError(t, w, "invalid_token")
}

func TestAuthUpstreamError(t *testing.T) {
	h := Auth(&mockValidator{err: &upstreamError{"github down"}})(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer tok")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusServiceUnavailable)
	}
	assertJSONError(t, w, "upstream_error")
}

func TestAuthValidToken(t *testing.T) {
	var gotIdentity, gotToken string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotIdentity = IdentityFromContext(r.Context())
		gotToken = TokenFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})

	h := Auth(&mockValidator{login: "alice"})(next)
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer my-token")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if gotIdentity != "alice" {
		t.Errorf("identity in context: got %q, want %q", gotIdentity, "alice")
	}
	if gotToken != "my-token" {
		t.Errorf("token in context: got %q, want %q", gotToken, "my-token")
	}
}

func assertJSONError(t *testing.T, w *httptest.ResponseRecorder, wantCode string) {
	t.Helper()
	var body map[string]string
	if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if body["error"] != wantCode {
		t.Errorf("error field: got %q, want %q", body["error"], wantCode)
	}
}

func assertWWWAuthenticate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	h := w.Header().Get("WWW-Authenticate")
	if h == "" {
		t.Error("WWW-Authenticate header missing")
	}
}
