package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// mockValidator implements TokenValidator for testing.
type mockValidator struct {
	login        string
	rotatedToken string
	err          error
	gotToken     string
	gotAudience  string
}

func (m *mockValidator) ValidateToken(_ context.Context, token, audience string) (string, string, error) {
	m.gotToken = token
	m.gotAudience = audience
	return m.login, m.rotatedToken, m.err
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
	assertJSONError(t, w, "invalid_request")
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

// TestAuthRotatedTokenReplacesContextToken verifies that when the validator
// reports a rotated access token, the Auth middleware substitutes it for the
// original bearer credential in the request context so that the reverse
// proxy forwards the fresh value to the upstream MCP server.
func TestAuthRotatedTokenReplacesContextToken(t *testing.T) {
	cases := []struct {
		name         string
		rotatedToken string
		wantToken    string
	}{
		{name: "no rotation: original token preserved", rotatedToken: "", wantToken: "my-token"},
		{name: "rotation: rotated token wins", rotatedToken: "new-token", wantToken: "new-token"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotToken string
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotToken = TokenFromContext(r.Context())
				w.WriteHeader(http.StatusOK)
			})
			h := Auth(&mockValidator{login: "alice", rotatedToken: tc.rotatedToken})(next)
			r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
			r.Header.Set("Authorization", "Bearer my-token")
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != http.StatusOK {
				t.Fatalf("status: got %d, want 200", w.Code)
			}
			if gotToken != tc.wantToken {
				t.Errorf("token in context: got %q, want %q", gotToken, tc.wantToken)
			}
		})
	}
}

func TestAuthPassesExpectedAudience(t *testing.T) {
	validator := &mockValidator{login: "alice"}
	h := Auth(validator,
		WithBaseURL("https://gateway.example.com"),
		WithAudience("https://gateway.example.com/mcp/copilot-review"),
	)(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp/copilot-review", nil)
	r.Header.Set("Authorization", "Bearer my-token")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	if validator.gotToken != "my-token" {
		t.Errorf("token: got %q, want my-token", validator.gotToken)
	}
	if validator.gotAudience != "https://gateway.example.com/mcp/copilot-review" {
		t.Errorf("audience: got %q", validator.gotAudience)
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
	if body["error_description"] == "" {
		t.Error("error_description field missing or empty")
	}
}

func assertWWWAuthenticate(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	h := w.Header().Get("WWW-Authenticate")
	if h == "" {
		t.Error("WWW-Authenticate header missing")
	}
}

func TestAuthMissingTokenWithBaseURL(t *testing.T) {
	h := Auth(&mockValidator{login: "alice"}, WithBaseURL("https://gateway.example.com"))(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
	if strings.Contains(wwwAuth, `error="invalid_request"`) {
		t.Errorf("WWW-Authenticate should not include error= for missing token (design choice): %q", wwwAuth)
	}
}

func TestAuthInvalidTokenWithBaseURL(t *testing.T) {
	h := Auth(&mockValidator{err: fmt.Errorf("bad token")}, WithBaseURL("https://gateway.example.com"))(http.HandlerFunc(okHandler))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	r.Header.Set("Authorization", "Bearer bad-token")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate missing error=invalid_token: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "error_description") {
		t.Errorf("WWW-Authenticate missing error_description: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "resource_metadata") {
		t.Errorf("WWW-Authenticate missing resource_metadata: %q", wwwAuth)
	}
	if !strings.Contains(wwwAuth, "/.well-known/oauth-protected-resource") {
		t.Errorf("WWW-Authenticate resource_metadata should point to /.well-known/oauth-protected-resource: %q", wwwAuth)
	}
}

// TestAuthWithResourceMetadataURL verifies that an explicit per-route PRM URL
// is emitted verbatim in resource_metadata, taking precedence over the URL
// derived from WithBaseURL. This is the path used by main.go to advertise
// per-route PRMs (MCP Authorization Spec 2025-06-18).
func TestAuthWithResourceMetadataURL(t *testing.T) {
	const routePRM = "https://gateway.example.com/.well-known/oauth-protected-resource/mcp/copilot-review"
	cases := []struct {
		name      string
		validator *mockValidator
		setAuth   bool
	}{
		{name: "missing token", validator: &mockValidator{login: "alice"}, setAuth: false},
		{name: "invalid token", validator: &mockValidator{err: fmt.Errorf("bad token")}, setAuth: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := Auth(tc.validator,
				WithBaseURL("https://gateway.example.com"),
				WithResourceMetadataURL(routePRM),
			)(http.HandlerFunc(okHandler))
			r := httptest.NewRequest(http.MethodGet, "/mcp/copilot-review", nil)
			if tc.setAuth {
				r.Header.Set("Authorization", "Bearer bad-token")
			}
			w := httptest.NewRecorder()

			h.ServeHTTP(w, r)

			if w.Code != http.StatusUnauthorized {
				t.Fatalf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
			}
			wwwAuth := w.Header().Get("WWW-Authenticate")
			want := fmt.Sprintf(`resource_metadata=%q`, routePRM)
			if !strings.Contains(wwwAuth, want) {
				t.Errorf("WWW-Authenticate: got %q, want substring %q", wwwAuth, want)
			}
			// The gateway-wide /.well-known/oauth-protected-resource must NOT
			// leak into the header when a per-route URL is configured.
			if strings.Contains(wwwAuth, `resource_metadata="https://gateway.example.com/.well-known/oauth-protected-resource"`) {
				t.Errorf("per-route URL should override gateway-wide PRM URL: %q", wwwAuth)
			}
		})
	}
}
