package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

func newTestHandler() *Handler {
	p := provider.NewGitHub(provider.GitHubConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-client-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
	})
	return NewHandler(Config{
		BaseURL:    "http://localhost:8080",
		SessionTTL: 10 * time.Minute,
		CacheTTL:   5 * time.Minute,
		ExpiresIn:  90 * 24 * time.Hour,
	}, p)
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

func TestNewHandlerPanicsOnNilProvider(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("expected panic for nil provider")
		}
	}()
	NewHandler(Config{}, nil)
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
