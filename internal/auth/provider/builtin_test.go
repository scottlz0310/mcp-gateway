package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func newBuiltinFromServer(t *testing.T, srv *httptest.Server) Provider {
	t.Helper()
	return NewBuiltin(GitHubConfig{
		ClientID:     "builtin-cid",
		ClientSecret: "builtin-secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "read:user,user:email",
		AuthorizeURL: srv.URL + "/login/oauth/authorize",
		TokenURL:     srv.URL + "/login/oauth/access_token",
		UserAPI:      srv.URL + "/user",
		HTTPClient:   srv.Client(),
	})
}

func TestBuiltinProviderName(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	if got := p.Name(); got != "builtin" {
		t.Errorf("Name(): got %q, want %q", got, "builtin")
	}
}

func TestBuiltinProviderClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	if got := p.ClientID(); got != "builtin-cid" {
		t.Errorf("ClientID(): got %q, want %q", got, "builtin-cid")
	}
}

func TestBuiltinProviderScopes(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	if got := p.Scopes(); got != "read:user,user:email" {
		t.Errorf("Scopes(): got %q, want %q", got, "read:user,user:email")
	}
}

func TestBuiltinAuthorizeURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	got := p.AuthorizeURL("mystate", "mychallenge")
	if got == "" {
		t.Error("AuthorizeURL returned empty string")
	}
	// Must contain the state param
	if want := "state=mystate"; !strings.Contains(got, want) {
		t.Errorf("AuthorizeURL %q missing %q", got, want)
	}
}

func TestBuiltinExchangeCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gh-tok","scope":"read:user"}`))
	}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	resp, err := p.ExchangeCode(context.Background(), "auth-code")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if resp.AccessToken != "gh-tok" {
		t.Errorf("AccessToken: got %q, want %q", resp.AccessToken, "gh-tok")
	}
}

func TestBuiltinRefreshTokenNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	_, err := p.RefreshToken(context.Background(), "some-token")
	if !errors.Is(err, ErrRefreshNotSupported) {
		t.Errorf("RefreshToken: expected ErrRefreshNotSupported, got %v", err)
	}
}

func TestBuiltinValidateTokenDelegatesToGitHub(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"login":"testuser","id":42,"email":"test@example.com","name":"Test User"}`))
	}))
	defer srv.Close()
	p := newBuiltinFromServer(t, srv)
	id, err := p.ValidateToken(context.Background(), "gh-access-token")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if id.Subject == "" {
		t.Error("ValidateToken: expected non-empty Subject")
	}
}

