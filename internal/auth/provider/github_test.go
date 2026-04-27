package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func newGitHubFromServer(t *testing.T, srv *httptest.Server) Provider {
	t.Helper()
	return NewGitHub(GitHubConfig{
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURI:  "http://localhost:8080/callback",
		Scopes:       "repo,user",
		AuthorizeURL: srv.URL + "/login/oauth/authorize",
		TokenURL:     srv.URL + "/login/oauth/access_token",
		UserAPI:      srv.URL + "/user",
		HTTPClient:   srv.Client(),
	})
}

func TestGitHubAuthorizeURL(t *testing.T) {
	p := NewGitHub(GitHubConfig{
		ClientID:    "cid",
		RedirectURI: "http://localhost:8080/callback",
		Scopes:      "repo,user",
	})
	got, err := url.Parse(p.AuthorizeURL("state-abc", "challenge-ignored"))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if got.Host != "github.com" {
		t.Errorf("host: got %q", got.Host)
	}
	q := got.Query()
	if q.Get("client_id") != "cid" {
		t.Errorf("client_id: got %q", q.Get("client_id"))
	}
	if q.Get("state") != "state-abc" {
		t.Errorf("state: got %q", q.Get("state"))
	}
	if q.Get("redirect_uri") != "http://localhost:8080/callback" {
		t.Errorf("redirect_uri: got %q", q.Get("redirect_uri"))
	}
	if q.Get("scope") != "repo,user" {
		t.Errorf("scope: got %q", q.Get("scope"))
	}
}

func TestGitHubExchangeCode(t *testing.T) {
	cases := []struct {
		name        string
		status      int
		body        string
		wantToken   string
		wantScopes  []string
		wantErr     bool
		wantUpstrm  bool
	}{
		{
			name:       "success",
			status:     http.StatusOK,
			body:       `{"access_token":"tok","scope":"repo,user"}`,
			wantToken:  "tok",
			wantScopes: []string{"repo", "user"},
		},
		{
			name:    "oauth error",
			status:  http.StatusOK,
			body:    `{"error":"bad_verification_code"}`,
			wantErr: true,
		},
		{
			name:    "empty token",
			status:  http.StatusOK,
			body:    `{"access_token":""}`,
			wantErr: true,
		},
		{
			name:       "5xx is upstream error",
			status:     http.StatusBadGateway,
			body:       "upstream",
			wantErr:    true,
			wantUpstrm: true,
		},
		{
			name:    "4xx is regular error",
			status:  http.StatusBadRequest,
			body:    "bad",
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/login/oauth/access_token" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			p := newGitHubFromServer(t, srv)
			tok, scopes, err := p.ExchangeCode(context.Background(), "code")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				var ue *UpstreamError
				if tc.wantUpstrm && !errors.As(err, &ue) {
					t.Errorf("expected UpstreamError, got %T: %v", err, err)
				}
				if !tc.wantUpstrm && errors.As(err, &ue) {
					t.Errorf("did not expect UpstreamError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tok != tc.wantToken {
				t.Errorf("token: got %q, want %q", tok, tc.wantToken)
			}
			if strings.Join(scopes, ",") != strings.Join(tc.wantScopes, ",") {
				t.Errorf("scopes: got %v, want %v", scopes, tc.wantScopes)
			}
		})
	}
}

func TestGitHubValidateToken(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		wantSub    string
		wantErr    bool
		wantUpstrm bool
	}{
		{
			name:    "success",
			status:  http.StatusOK,
			body:    `{"login":"alice","name":"Alice"}`,
			wantSub: "alice",
		},
		{
			name:    "401 invalid token",
			status:  http.StatusUnauthorized,
			body:    "",
			wantErr: true,
		},
		{
			name:       "5xx upstream",
			status:     http.StatusInternalServerError,
			body:       "",
			wantErr:    true,
			wantUpstrm: true,
		},
		{
			name:    "empty login",
			status:  http.StatusOK,
			body:    `{"login":""}`,
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/user" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if got := r.Header.Get("Authorization"); got != "Bearer my-token" {
					t.Errorf("Authorization: got %q", got)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			p := newGitHubFromServer(t, srv)
			id, err := p.ValidateToken(context.Background(), "my-token")
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error")
				}
				var ue *UpstreamError
				if tc.wantUpstrm && !errors.As(err, &ue) {
					t.Errorf("expected UpstreamError, got %T", err)
				}
				if !tc.wantUpstrm && errors.As(err, &ue) {
					t.Errorf("did not expect UpstreamError, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id.Subject != tc.wantSub {
				t.Errorf("subject: got %q, want %q", id.Subject, tc.wantSub)
			}
			if id.Provider != "github" {
				t.Errorf("provider: got %q", id.Provider)
			}
		})
	}
}

func TestNewFactory(t *testing.T) {
	t.Run("github default", func(t *testing.T) {
		p, err := New(Config{
			ClientID:     "cid",
			ClientSecret: "secret",
			RedirectURI:  "http://localhost/callback",
			Scopes:       "repo",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if p.Name() != "github" {
			t.Errorf("name: got %q", p.Name())
		}
	})
	t.Run("missing credentials", func(t *testing.T) {
		_, err := New(Config{Kind: "github"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unsupported kind", func(t *testing.T) {
		_, err := New(Config{Kind: "unknown", ClientID: "x", ClientSecret: "y"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
