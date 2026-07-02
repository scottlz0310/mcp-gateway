package provider

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
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

func TestNewGitHubPanicsOnInvalidAuthorizeURL(t *testing.T) {
	cases := []struct {
		name         string
		authorizeURL string
	}{
		{name: "relative URL", authorizeURL: "login/oauth/authorize"},
		{name: "non-http scheme", authorizeURL: "ftp://github.com/login/oauth/authorize"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r == nil {
					t.Error("expected panic but did not get one")
				}
			}()
			NewGitHub(GitHubConfig{
				ClientID:     "cid",
				ClientSecret: "secret",
				RedirectURI:  "http://localhost:8080/callback",
				AuthorizeURL: tc.authorizeURL,
			})
		})
	}
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
		name              string
		status            int
		body              string
		wantToken         string
		wantScopes        []string
		wantRefresh       string
		wantAccessExpiry  time.Duration
		wantRefreshExpiry time.Duration
		wantErr           bool
		wantUpstrm        bool
	}{
		{
			name:       "success non-expiring",
			status:     http.StatusOK,
			body:       `{"access_token":"tok","scope":"repo,user"}`,
			wantToken:  "tok",
			wantScopes: []string{"repo", "user"},
		},
		{
			name:       "success ghu_ prefix (GitHub Apps user-to-server)",
			status:     http.StatusOK,
			body:       `{"access_token":"ghu_abc123","scope":"repo,user"}`,
			wantToken:  "ghu_abc123",
			wantScopes: []string{"repo", "user"},
		},
		{
			name:              "success with ghu_ access token and ghr_ refresh token (GitHub Apps expiring)",
			status:            http.StatusOK,
			body:              `{"access_token":"ghu_access","scope":"repo","refresh_token":"ghr_refresh","expires_in":28800,"refresh_token_expires_in":15897600}`,
			wantToken:         "ghu_access",
			wantScopes:        []string{"repo"},
			wantRefresh:       "ghr_refresh",
			wantAccessExpiry:  28800 * time.Second,
			wantRefreshExpiry: 15897600 * time.Second,
		},
		{
			name:              "success with refresh token",
			status:            http.StatusOK,
			body:              `{"access_token":"tok","scope":"repo","refresh_token":"rt","expires_in":28800,"refresh_token_expires_in":15897600}`,
			wantToken:         "tok",
			wantScopes:        []string{"repo"},
			wantRefresh:       "rt",
			wantAccessExpiry:  28800 * time.Second,
			wantRefreshExpiry: 15897600 * time.Second,
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
			resp, err := p.ExchangeCode(context.Background(), "code")
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
			if resp.AccessToken != tc.wantToken {
				t.Errorf("access_token: got %q, want %q", resp.AccessToken, tc.wantToken)
			}
			if strings.Join(resp.Scopes, ",") != strings.Join(tc.wantScopes, ",") {
				t.Errorf("scopes: got %v, want %v", resp.Scopes, tc.wantScopes)
			}
			if resp.RefreshToken != tc.wantRefresh {
				t.Errorf("refresh_token: got %q, want %q", resp.RefreshToken, tc.wantRefresh)
			}
			if resp.AccessTokenExpiresIn != tc.wantAccessExpiry {
				t.Errorf("access expiry: got %v, want %v", resp.AccessTokenExpiresIn, tc.wantAccessExpiry)
			}
			if resp.RefreshTokenExpiresIn != tc.wantRefreshExpiry {
				t.Errorf("refresh expiry: got %v, want %v", resp.RefreshTokenExpiresIn, tc.wantRefreshExpiry)
			}
		})
	}
}

func TestGitHubOAuthErrorIsTypedAndRedacted(t *testing.T) {
	const providerDescription = "sensitive provider response details"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"` + providerDescription + `"}`))
	}))
	defer srv.Close()

	p := newGitHubFromServer(t, srv)
	_, err := p.ExchangeCode(context.Background(), "secret-authorization-code")
	if err == nil {
		t.Fatal("expected error")
	}
	var oauthErr *OAuthError
	if !errors.As(err, &oauthErr) {
		t.Fatalf("error type: got %T, want *OAuthError", err)
	}
	if oauthErr.Code != "invalid_grant" || oauthErr.HTTPStatus != http.StatusBadRequest {
		t.Errorf("OAuthError: got %#v", oauthErr)
	}
	if strings.Contains(err.Error(), providerDescription) || strings.Contains(err.Error(), "secret-authorization-code") {
		t.Errorf("error leaked provider or request secret: %v", err)
	}
	code, status, transient := ErrorDetails(err)
	if code != "invalid_grant" || status != http.StatusBadRequest || transient {
		t.Errorf("ErrorDetails: got code=%q status=%d transient=%v", code, status, transient)
	}
}

func TestNormalizeOAuthErrorCode(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{input: "invalid_grant", want: "invalid_grant"},
		{input: " access_denied ", want: "access_denied"},
		{input: "Authorization_Pending", want: "authorization_pending"},
		{input: "incorrect_client_credentials", want: "incorrect_client_credentials"},
		{input: "unknown_error", want: "unknown_error"},
		// 未知値は fail-closed で固定値へ: 文字種・長さが正当でも、AS が
		// 秘密値を error フィールドへ反映したケースを素通ししない。
		{input: "access-denied", want: "unknown_error"},
		{input: "client-secret-MUST-NOT-LOG", want: "unknown_error"},
		{input: "bad.value", want: "unknown_error"},
		{input: "bad value", want: "unknown_error"},
		{input: strings.Repeat("x", 65), want: "unknown_error"},
		{input: "", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			if got := NormalizeOAuthErrorCode(tc.input); got != tc.want {
				t.Errorf("NormalizeOAuthErrorCode(%q): got %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestGitHubRefreshToken exercises the rotation path against a fake GitHub
// token endpoint.
func TestGitHubRefreshToken(t *testing.T) {
	cases := []struct {
		name              string
		refreshTokenInput string
		status            int
		body              string
		wantToken         string
		wantRefresh       string
		wantAccessExpiry  time.Duration
		wantErr           bool
		wantUpstrm        bool
	}{
		{
			name:              "success rotates tokens",
			refreshTokenInput: "rt-old",
			status:            http.StatusOK,
			body:              `{"access_token":"new","refresh_token":"rt-new","scope":"repo","expires_in":28800,"refresh_token_expires_in":15897600}`,
			wantToken:         "new",
			wantRefresh:       "rt-new",
			wantAccessExpiry:  28800 * time.Second,
		},
		{
			name:              "success ghr_ refresh returns ghu_ access (GitHub Apps expiring)",
			refreshTokenInput: "ghr_oldrefresh",
			status:            http.StatusOK,
			body:              `{"access_token":"ghu_newaccess","refresh_token":"ghr_newrefresh","scope":"repo","expires_in":28800,"refresh_token_expires_in":15897600}`,
			wantToken:         "ghu_newaccess",
			wantRefresh:       "ghr_newrefresh",
			wantAccessExpiry:  28800 * time.Second,
		},
		{
			name:              "bad refresh token rejected",
			refreshTokenInput: "rt-bad",
			status:            http.StatusOK,
			body:              `{"error":"bad_refresh_token"}`,
			wantErr:           true,
		},
		{
			name:              "upstream 503 is transient",
			refreshTokenInput: "rt-x",
			status:            http.StatusServiceUnavailable,
			body:              "down",
			wantErr:           true,
			wantUpstrm:        true,
		},
		{
			name:              "empty input rejected without HTTP call",
			refreshTokenInput: "",
			status:            http.StatusOK,
			body:              `{"access_token":"unused"}`,
			wantErr:           true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var observed url.Values
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/login/oauth/access_token" {
					t.Errorf("unexpected path: %s", r.URL.Path)
				}
				if err := r.ParseForm(); err != nil {
					t.Errorf("parse form: %v", err)
				}
				observed = r.Form
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			p := newGitHubFromServer(t, srv)
			resp, err := p.RefreshToken(context.Background(), tc.refreshTokenInput)
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
			if got := observed.Get("grant_type"); got != "refresh_token" {
				t.Errorf("grant_type form: got %q", got)
			}
			if got := observed.Get("refresh_token"); got != tc.refreshTokenInput {
				t.Errorf("refresh_token form: got %q, want %q", got, tc.refreshTokenInput)
			}
			if resp.AccessToken != tc.wantToken {
				t.Errorf("access_token: got %q, want %q", resp.AccessToken, tc.wantToken)
			}
			if resp.RefreshToken != tc.wantRefresh {
				t.Errorf("refresh_token: got %q, want %q", resp.RefreshToken, tc.wantRefresh)
			}
			if resp.AccessTokenExpiresIn != tc.wantAccessExpiry {
				t.Errorf("access expiry: got %v, want %v", resp.AccessTokenExpiresIn, tc.wantAccessExpiry)
			}
		})
	}
}

func TestGitHubValidateToken(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		body       string
		headers    map[string]string
		wantSub    string
		wantErr    bool
		wantUpstrm bool
		wantCode   string
	}{
		{
			name:    "success",
			status:  http.StatusOK,
			body:    `{"login":"alice","name":"Alice"}`,
			wantSub: "alice",
		},
		{
			name:     "401 invalid token",
			status:   http.StatusUnauthorized,
			body:     "",
			wantErr:  true,
			wantCode: "invalid_token",
		},
		{
			name:       "5xx upstream",
			status:     http.StatusInternalServerError,
			body:       "",
			wantErr:    true,
			wantUpstrm: true,
		},
		{
			name:     "403 access denied is permanent",
			status:   http.StatusForbidden,
			body:     "",
			wantErr:  true,
			wantCode: "access_denied",
		},
		{
			name:       "403 primary rate limit is transient",
			status:     http.StatusForbidden,
			body:       "",
			headers:    map[string]string{"X-RateLimit-Remaining": "0"},
			wantErr:    true,
			wantUpstrm: true,
			wantCode:   "rate_limited",
		},
		{
			name:       "429 is upstream error",
			status:     http.StatusTooManyRequests,
			body:       "",
			wantErr:    true,
			wantUpstrm: true,
			wantCode:   "rate_limited",
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
				for key, value := range tc.headers {
					w.Header().Set(key, value)
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
				if tc.status != http.StatusOK {
					code, status, transient := ErrorDetails(err)
					if code != tc.wantCode || status != tc.status || transient != tc.wantUpstrm {
						t.Errorf("ErrorDetails: got (%q, %d, %v), want (%q, %d, %v)",
							code, status, transient, tc.wantCode, tc.status, tc.wantUpstrm)
					}
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
	t.Run("missing redirect uri", func(t *testing.T) {
		_, err := New(Config{Kind: "github", ClientID: "cid", ClientSecret: "secret"})
		if err == nil {
			t.Fatal("expected error for missing RedirectURI")
		}
	})
	t.Run("invalid redirect uri", func(t *testing.T) {
		_, err := New(Config{Kind: "github", ClientID: "cid", ClientSecret: "secret", RedirectURI: "not-a-url"})
		if err == nil {
			t.Fatal("expected error for non-absolute RedirectURI")
		}
	})
	t.Run("redirect uri missing host", func(t *testing.T) {
		_, err := New(Config{Kind: "github", ClientID: "cid", ClientSecret: "secret", RedirectURI: "https:///callback"})
		if err == nil {
			t.Fatal("expected error for RedirectURI with empty host")
		}
	})
	t.Run("redirect uri with fragment", func(t *testing.T) {
		_, err := New(Config{Kind: "github", ClientID: "cid", ClientSecret: "secret", RedirectURI: "https://example.com/callback#frag"})
		if err == nil {
			t.Fatal("expected error for RedirectURI with fragment")
		}
	})
	t.Run("unsupported kind", func(t *testing.T) {
		_, err := New(Config{Kind: "unknown", ClientID: "x", ClientSecret: "y"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}
