package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCProvider_Success(t *testing.T) {
	// 1. Setup mock OIDC server
	mux := http.NewServeMux()

	// Mock discovery doc
	var mockServerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": mockServerURL + "/auth",
			"token_endpoint":         mockServerURL + "/token",
			"userinfo_endpoint":      mockServerURL + "/userinfo",
			"jwks_uri":               mockServerURL + "/jwks",
			"issuer":                 mockServerURL,
		})
	})

	// Mock Token Endpoint
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST to token endpoint, got %s", r.Method)
		}
		_ = r.ParseForm()

		grantType := r.FormValue("grant_type")
		switch grantType {
		case "authorization_code":
			if r.FormValue("code") != "valid-code" || r.FormValue("client_id") != "test-client" || r.FormValue("client_secret") != "test-secret" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"token-abc","refresh_token":"refresh-123","expires_in":3600,"scope":"openid profile"}`))
		case "refresh_token":
			if r.FormValue("refresh_token") != "refresh-123" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"token-def","refresh_token":"refresh-456","expires_in":3600}`))
		default:
			t.Errorf("unexpected grant_type: %s", grantType)
		}
	})

	// Mock UserInfo Endpoint
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		switch auth {
		case "Bearer token-abc":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"user-123","name":"Jane Doe","preferred_username":"janedoe","email":"jane@example.com"}`))
		case "Bearer token-def":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"sub":"user-123","preferred_username":"janedoe"}`))
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	mockServerURL = server.URL

	// 2. Initialize OIDC Provider
	prov, err := NewOIDC(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/cb",
		Scopes:       "openid email",
		IssuerURL:    mockServerURL,
	})
	if err != nil {
		t.Fatalf("NewOIDC failed: %v", err)
	}

	// 3. Test Provider info
	if prov.Name() != "oidc" {
		t.Errorf("expected name 'oidc', got %q", prov.Name())
	}
	if prov.ClientID() != "test-client" {
		t.Errorf("expected client_id 'test-client', got %q", prov.ClientID())
	}
	if prov.Scopes() != "openid email" {
		t.Errorf("expected scopes 'openid email', got %q", prov.Scopes())
	}

	// 4. Test AuthorizeURL
	authURLStr := prov.AuthorizeURL("state-123", "challenge-xyz")
	authURL, err := url.Parse(authURLStr)
	if err != nil {
		t.Fatalf("failed to parse auth URL: %v", err)
	}
	if authURL.Path != "/auth" {
		t.Errorf("expected path '/auth', got %q", authURL.Path)
	}
	q := authURL.Query()
	if q.Get("client_id") != "test-client" {
		t.Errorf("expected client_id 'test-client', got %q", q.Get("client_id"))
	}
	if q.Get("redirect_uri") != "http://localhost/cb" {
		t.Errorf("expected redirect_uri 'http://localhost/cb', got %q", q.Get("redirect_uri"))
	}
	if q.Get("state") != "state-123" {
		t.Errorf("expected state 'state-123', got %q", q.Get("state"))
	}
	if q.Get("scope") != "openid email" {
		t.Errorf("expected scope 'openid email', got %q", q.Get("scope"))
	}
	if q.Get("code_challenge") != "challenge-xyz" {
		t.Errorf("expected code_challenge 'challenge-xyz', got %q", q.Get("code_challenge"))
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("expected code_challenge_method 'S256', got %q", q.Get("code_challenge_method"))
	}

	// 5. Test ExchangeCode
	ctx := context.Background()
	tokens, err := prov.ExchangeCode(ctx, "valid-code")
	if err != nil {
		t.Fatalf("ExchangeCode failed: %v", err)
	}
	if tokens.AccessToken != "token-abc" {
		t.Errorf("expected access_token 'token-abc', got %q", tokens.AccessToken)
	}
	if tokens.RefreshToken != "refresh-123" {
		t.Errorf("expected refresh_token 'refresh-123', got %q", tokens.RefreshToken)
	}
	if len(tokens.Scopes) != 2 || tokens.Scopes[0] != "openid" || tokens.Scopes[1] != "profile" {
		t.Errorf("unexpected scopes: %v", tokens.Scopes)
	}
	if tokens.AccessTokenExpiresIn != 3600*time.Second {
		t.Errorf("expected expires_in 3600s, got %v", tokens.AccessTokenExpiresIn)
	}

	// 6. Test ValidateToken
	identity, err := prov.ValidateToken(ctx, "token-abc")
	if err != nil {
		t.Fatalf("ValidateToken failed: %v", err)
	}
	if identity.Provider != "oidc" {
		t.Errorf("expected provider 'oidc', got %q", identity.Provider)
	}
	if identity.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", identity.Subject)
	}
	if identity.DisplayName != "janedoe" {
		t.Errorf("expected display_name 'janedoe', got %q", identity.DisplayName)
	}

	// 7. Test RefreshToken
	rotated, err := prov.RefreshToken(ctx, "refresh-123")
	if err != nil {
		t.Fatalf("RefreshToken failed: %v", err)
	}
	if rotated.AccessToken != "token-def" {
		t.Errorf("expected rotated access_token 'token-def', got %q", rotated.AccessToken)
	}
	if rotated.RefreshToken != "refresh-456" {
		t.Errorf("expected rotated refresh_token 'refresh-456', got %q", rotated.RefreshToken)
	}

	// 8. Test ValidateToken with rotated token
	identityRotated, err := prov.ValidateToken(ctx, rotated.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken for rotated token failed: %v", err)
	}
	if identityRotated.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got %q", identityRotated.Subject)
	}
}

func TestOIDCProvider_DiscoveryFailure(t *testing.T) {
	_, err := NewOIDC(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/cb",
		IssuerURL:    "http://127.0.0.1:54321", // Non-existent port
	})
	if err == nil {
		t.Error("expected NewOIDC to fail due to unreachable discovery endpoint")
	}
	if !strings.Contains(err.Error(), "failed to fetch discovery doc") {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestOIDCProvider_InvalidUserInfo(t *testing.T) {
	mux := http.NewServeMux()
	var mockServerURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": mockServerURL + "/auth",
			"token_endpoint":         mockServerURL + "/token",
			"userinfo_endpoint":      mockServerURL + "/userinfo",
		})
	})
	mux.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	})

	server := httptest.NewServer(mux)
	defer server.Close()
	mockServerURL = server.URL

	prov, err := NewOIDC(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/cb",
		IssuerURL:    mockServerURL,
	})
	if err != nil {
		t.Fatalf("NewOIDC failed: %v", err)
	}

	_, err = prov.ValidateToken(context.Background(), "invalid-token")
	if err == nil {
		t.Error("expected ValidateToken to fail for unauthorized status")
	}
}

func TestOIDCProviderTokenErrorIsTypedAndRedacted(t *testing.T) {
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"authorization_endpoint": serverURL + "/auth",
			"token_endpoint":         serverURL + "/token",
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"sensitive OIDC details"}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()
	serverURL = server.URL

	prov, err := NewOIDC(OIDCConfig{
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost/cb",
		IssuerURL:    serverURL,
	})
	if err != nil {
		t.Fatalf("NewOIDC: %v", err)
	}
	_, err = prov.ExchangeCode(context.Background(), "secret-code")
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
	if strings.Contains(err.Error(), "sensitive OIDC details") || strings.Contains(err.Error(), "secret-code") {
		t.Errorf("error leaked provider or request secret: %v", err)
	}
}
