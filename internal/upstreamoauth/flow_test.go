package upstreamoauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

func withIdentity(r *http.Request, subject string) *http.Request {
	return r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyIdentity, subject))
}

func TestAuthorizeMiddleware_Unauthenticated(t *testing.T) {
	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	mw := upstreamoauth.NewAuthorizeMiddleware(
		"myroute", "https://as.example.com", "", "authorization_code", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for unauthenticated request")
	}))

	req := httptest.NewRequest("GET", "/mcp/myroute/sse", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusUnauthorized)
	}
}

func TestAuthorizeMiddleware_ValidToken_PassThrough(t *testing.T) {
	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("alice@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "existing-token",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	mw := upstreamoauth.NewAuthorizeMiddleware(
		"myroute", "https://as.example.com", "", "authorization_code", "", mgr,
		upstreamoauth.NewStateStore(), tokenStore, "http://localhost:8080",
	)
	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp/myroute/sse", nil)
	req = withIdentity(req, "alice@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}
	if !nextCalled {
		t.Error("expected next handler to be called when valid token exists")
	}
}

func TestAuthorizeMiddleware_RedirectWithPKCE(t *testing.T) {
	const (
		routeName = "myroute"
		publicURL = "http://localhost:8080"
		subject   = "bob@example.com"
	)

	// Pre-register a client so EnsureClient short-circuits without network I/O.
	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		routeName: {
			RouteName:             routeName,
			Issuer:                "https://as.example.com",
			AuthorizationEndpoint: "https://as.example.com/authorize",
			TokenEndpoint:         "https://as.example.com/token",
			ClientID:              "client-id",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, publicURL)

	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	mw := upstreamoauth.NewAuthorizeMiddleware(
		routeName, "https://as.example.com", "read write", "authorization_code", "", mgr, stateStore, tokenStore, publicURL,
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when redirect is expected")
	}))

	req := httptest.NewRequest("GET", "/mcp/myroute/sse", nil)
	req = withIdentity(req, subject)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusFound, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	if loc == "" {
		t.Fatal("expected Location header in redirect response")
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("invalid Location URL: %v", err)
	}
	q := u.Query()

	if q.Get("client_id") != "client-id" {
		t.Errorf("client_id = %q, want %q", q.Get("client_id"), "client-id")
	}
	wantRedirectURI := publicURL + "/upstream/callback/" + routeName
	if q.Get("redirect_uri") != wantRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", q.Get("redirect_uri"), wantRedirectURI)
	}
	if q.Get("response_type") != "code" {
		t.Errorf("response_type = %q, want %q", q.Get("response_type"), "code")
	}
	if q.Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want %q", q.Get("code_challenge_method"), "S256")
	}
	if q.Get("code_challenge") == "" {
		t.Error("code_challenge must not be empty")
	}
	if q.Get("scope") != "read write" {
		t.Errorf("scope = %q, want %q", q.Get("scope"), "read write")
	}

	stateKey := q.Get("state")
	if stateKey == "" {
		t.Fatal("state parameter must not be empty")
	}
	savedState, ok := stateStore.Pop(stateKey)
	if !ok {
		t.Fatal("state key must be saved in StateStore")
	}
	if savedState.Subject != subject {
		t.Errorf("state.Subject = %q, want %q", savedState.Subject, subject)
	}
	if savedState.RouteName != routeName {
		t.Errorf("state.RouteName = %q, want %q", savedState.RouteName, routeName)
	}
	if savedState.CodeVerifier == "" {
		t.Error("state.CodeVerifier must not be empty")
	}
}

func TestAuthorizeMiddleware_ScopeOmitted(t *testing.T) {
	const routeName = "myroute"

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		routeName: {
			RouteName:             routeName,
			AuthorizationEndpoint: "https://as.example.com/authorize",
			ClientID:              "cid",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	mw := upstreamoauth.NewAuthorizeMiddleware(
		routeName, "https://as.example.com", "", "authorization_code", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	req := httptest.NewRequest("GET", "/mcp/myroute/sse", nil)
	req = withIdentity(req, "user@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusFound)
	}
	loc := rr.Header().Get("Location")
	u, _ := url.Parse(loc)
	if u.Query().Get("scope") != "" {
		t.Errorf("scope must be omitted when upstreamOAuthScope is empty, got %q", u.Query().Get("scope"))
	}
}

func TestAuthorizeMiddleware_EnsureClientError(t *testing.T) {
	// AS returns 404 → discovery fails → EnsureClient error → 502.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	mw := upstreamoauth.NewAuthorizeMiddleware(
		"myroute", ts.URL, "", "authorization_code", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called on EnsureClient error")
	}))

	req := httptest.NewRequest("GET", "/mcp/myroute/sse", nil)
	req = withIdentity(req, "user@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
}

func TestAuthorizeMiddleware_ClientCredentials_Success(t *testing.T) {
	const (
		routeName   = "cc-route"
		publicURL   = "http://localhost:8080"
		subject     = "svc@example.com"
		accessToken = "cc-access-token"
	)

	// Fake token endpoint that returns a client_credentials token.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" {
			http.NotFound(w, r)
			return
		}
		if err := r.ParseForm(); err != nil {
			http.Error(w, "bad form", http.StatusBadRequest)
			return
		}
		if r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, "wrong grant_type", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": accessToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer tokenSrv.Close()

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		routeName: {
			RouteName:     routeName,
			Grant:         "client_credentials",
			Issuer:        tokenSrv.URL,
			TokenEndpoint: tokenSrv.URL + "/token",
			ClientID:      "svc-client",
			ClientSecret:  "svc-secret",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, publicURL)
	tokenStore := auth.NewMemUpstreamTokenStore()

	mw := upstreamoauth.NewAuthorizeMiddleware(
		routeName, tokenSrv.URL, "read", "client_credentials", "", mgr,
		upstreamoauth.NewStateStore(), tokenStore, publicURL,
	)
	nextCalled := false
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nextCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp/cc-route/sse", nil)
	req = withIdentity(req, subject)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}
	if !nextCalled {
		t.Error("expected next handler to be called after client_credentials token acquired")
	}

	// Verify the token was stored.
	rec, ok := tokenStore.Lookup(subject, routeName)
	if !ok {
		t.Fatal("expected token to be stored in tokenStore")
	}
	if rec.AccessToken != accessToken {
		t.Errorf("AccessToken = %q, want %q", rec.AccessToken, accessToken)
	}
}

func TestAuthorizeMiddleware_ClientCredentials_TokenEndpointError(t *testing.T) {
	// Token endpoint returns 500.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "server error", http.StatusInternalServerError)
	}))
	defer tokenSrv.Close()

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		"cc-err": {
			RouteName:     "cc-err",
			TokenEndpoint: tokenSrv.URL + "/token",
			ClientID:      "cid",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")

	mw := upstreamoauth.NewAuthorizeMiddleware(
		"cc-err", tokenSrv.URL, "", "client_credentials", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when token endpoint returns error")
	}))

	req := httptest.NewRequest("GET", "/mcp/cc-err/sse", nil)
	req = withIdentity(req, "svc@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
}

func TestAuthorizeMiddleware_ClientCredentials_MissingExpiresIn(t *testing.T) {
	// Token endpoint returns token without expires_in.
	tokenSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "no-expiry-token",
			"token_type":   "Bearer",
			// expires_in absent → zero value
		})
	}))
	defer tokenSrv.Close()

	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		"cc-noexp": {
			RouteName:     "cc-noexp",
			TokenEndpoint: tokenSrv.URL + "/token",
			ClientID:      "cid",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")

	mw := upstreamoauth.NewAuthorizeMiddleware(
		"cc-noexp", tokenSrv.URL, "", "client_credentials", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when expires_in is missing")
	}))

	req := httptest.NewRequest("GET", "/mcp/cc-noexp/sse", nil)
	req = withIdentity(req, "svc@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadGateway)
	}
}

func TestAuthorizeMiddleware_DefaultGrant_IsAuthCode(t *testing.T) {
	// grant="" should default to authorization_code (redirect, not client_credentials fetch).
	const routeName = "default-grant"
	cs := &testClientStore{records: map[string]upstreamoauth.ClientRecord{
		routeName: {
			RouteName:             routeName,
			AuthorizationEndpoint: "https://as.example.com/authorize",
			ClientID:              "cid",
		},
	}}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	mw := upstreamoauth.NewAuthorizeMiddleware(
		routeName, "https://as.example.com", "", "", "", mgr,
		upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), "http://localhost:8080",
	)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called: should redirect")
	}))

	req := httptest.NewRequest("GET", "/mcp/default-grant/sse", nil)
	req = withIdentity(req, "user@example.com")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("status = %d, want %d (empty grant should default to authorization_code)", rr.Code, http.StatusFound)
	}
}
