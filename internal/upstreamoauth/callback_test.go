package upstreamoauth_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

// testClientStore is a minimal in-memory ClientStore for testing.
type testClientStore struct {
	records map[string]upstreamoauth.ClientRecord
}

func (s *testClientStore) Load(routeName string) (upstreamoauth.ClientRecord, bool) {
	r, ok := s.records[routeName]
	return r, ok
}

func (s *testClientStore) Save(record upstreamoauth.ClientRecord) error {
	s.records[record.RouteName] = record
	return nil
}

func (s *testClientStore) All() []upstreamoauth.ClientRecord {
	out := make([]upstreamoauth.ClientRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out
}

func makeTokenServer(t *testing.T, response any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(response)
	}))
}

func makeCallbackHandler(
	stateStore upstreamoauth.StateStore,
	clientRecords map[string]upstreamoauth.ClientRecord,
	tokenStore auth.UpstreamTokenStore,
	publicURL string,
	httpClient *http.Client,
) *upstreamoauth.CallbackHandler {
	cs := &testClientStore{records: clientRecords}
	mgr := upstreamoauth.NewManager(cs, publicURL)
	return upstreamoauth.NewCallbackHandler(stateStore, mgr, tokenStore, publicURL, httpClient)
}

func TestCallbackHandler_Success(t *testing.T) {
	ts := makeTokenServer(t, map[string]any{
		"access_token":  "tok123",
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": "ref456",
		"scope":         "read write",
	})
	defer ts.Close()

	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	codeVerifier, _ := upstreamoauth.GenerateCodeVerifier()
	stateStore.Save("state-key", upstreamoauth.OAuthState{
		Subject:      "user@example.com",
		RouteName:    "myroute",
		OriginalPath: "/mcp/myroute",
		CodeVerifier: codeVerifier,
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			Issuer:        "https://upstream.example.com",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
		},
	}, tokenStore, "http://localhost:8080", ts.Client())

	req := httptest.NewRequest("GET", "/upstream/callback/myroute?state=state-key&code=auth-code", nil)
	req.SetPathValue("routeName", "myroute")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body=%s", rr.Code, http.StatusOK, rr.Body.String())
	}

	rec, ok := tokenStore.Lookup("user@example.com", "myroute")
	if !ok {
		t.Fatal("expected token to be saved in UpstreamTokenStore")
	}
	if rec.AccessToken != "tok123" {
		t.Errorf("AccessToken = %q, want %q", rec.AccessToken, "tok123")
	}
	if rec.RefreshToken != "ref456" {
		t.Errorf("RefreshToken = %q, want %q", rec.RefreshToken, "ref456")
	}
	if rec.ExpiresAt.IsZero() {
		t.Error("ExpiresAt must not be zero when expires_in > 0")
	}
}

func TestCallbackHandler_InvalidState(t *testing.T) {
	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{},
		tokenStore, "http://localhost:8080", nil)

	req := httptest.NewRequest("GET", "/upstream/callback/myroute?state=nonexistent&code=auth-code", nil)
	req.SetPathValue("routeName", "myroute")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCallbackHandler_RouteMismatch(t *testing.T) {
	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	stateStore.Save("state-key", upstreamoauth.OAuthState{
		Subject:      "user",
		RouteName:    "route-a", // state is for route-a
		CodeVerifier: "verifier",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{},
		tokenStore, "http://localhost:8080", nil)

	// callback arrives for route-b
	req := httptest.NewRequest("GET", "/upstream/callback/route-b?state=state-key&code=code", nil)
	req.SetPathValue("routeName", "route-b")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
}

func TestCallbackHandler_SubjectFromStateNotFromContext(t *testing.T) {
	// Verifies subject is recovered from StateStore, not middleware.IdentityFromContext.
	// The request has no auth middleware context (identity = "").
	const subject = "alice@example.com"

	ts := makeTokenServer(t, map[string]any{
		"access_token": "tok-alice",
		"token_type":   "Bearer",
		"expires_in":   3600,
	})
	defer ts.Close()

	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	stateStore.Save("s", upstreamoauth.OAuthState{
		Subject:      subject,
		RouteName:    "myroute",
		CodeVerifier: "ver",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, tokenStore, "http://localhost:8080", ts.Client())

	// No auth middleware context — IdentityFromContext returns "".
	req := httptest.NewRequest("GET", "/upstream/callback/myroute?state=s&code=c", nil)
	req.SetPathValue("routeName", "myroute")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}
	_, ok := tokenStore.Lookup(subject, "myroute")
	if !ok {
		t.Error("expected token to be saved using subject from state store, not from middleware context")
	}
}

func TestCallbackHandler_RedirectURIConstruction(t *testing.T) {
	const publicURL = "https://gateway.example.com"
	const routeName = "cloudflare"

	var capturedForm url.Values
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err == nil {
			capturedForm = r.Form
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"tok","token_type":"Bearer","expires_in":3600}`))
	}))
	defer ts.Close()

	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	stateStore.Save("s", upstreamoauth.OAuthState{
		Subject:      "user",
		RouteName:    routeName,
		CodeVerifier: "ver",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{
		routeName: {
			RouteName:     routeName,
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, tokenStore, publicURL, ts.Client())

	req := httptest.NewRequest("GET", "/upstream/callback/"+routeName+"?state=s&code=c", nil)
	req.SetPathValue("routeName", routeName)
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rr.Code, rr.Body.String())
	}

	wantRedirectURI := publicURL + "/upstream/callback/" + routeName
	if capturedForm.Get("redirect_uri") != wantRedirectURI {
		t.Errorf("redirect_uri = %q, want %q", capturedForm.Get("redirect_uri"), wantRedirectURI)
	}
}

func TestCallbackHandler_MissingCode_ErrorParam(t *testing.T) {
	// Upstream AS denies authorization and returns error=access_denied (no code).
	// The state must still be consumed (Pop) to prevent reuse.
	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	stateStore.Save("s", upstreamoauth.OAuthState{
		Subject:      "user",
		RouteName:    "myroute",
		CodeVerifier: "ver",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{},
		tokenStore, "http://localhost:8080", nil)

	req := httptest.NewRequest("GET", "/upstream/callback/myroute?state=s&error=access_denied", nil)
	req.SetPathValue("routeName", "myroute")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusBadRequest)
	}
	// State must have been consumed: a second request with the same state must fail.
	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/upstream/callback/myroute?state=s&code=code2", nil)
	req2.SetPathValue("routeName", "myroute")
	handler.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusBadRequest {
		t.Errorf("state reuse after error: status = %d, want %d (state should be consumed)", rr2.Code, http.StatusBadRequest)
	}
}

func TestCallbackHandler_MissingExpiresIn(t *testing.T) {
	// Token response without expires_in must be rejected (zero ExpiresAt is unsafe).
	ts := makeTokenServer(t, map[string]any{
		"access_token": "tok",
		"token_type":   "Bearer",
		// expires_in intentionally omitted
	})
	defer ts.Close()

	stateStore := upstreamoauth.NewStateStore()
	tokenStore := auth.NewMemUpstreamTokenStore()

	stateStore.Save("s", upstreamoauth.OAuthState{
		Subject:      "user",
		RouteName:    "myroute",
		CodeVerifier: "ver",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	})

	handler := makeCallbackHandler(stateStore, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, tokenStore, "http://localhost:8080", ts.Client())

	req := httptest.NewRequest("GET", "/upstream/callback/myroute?state=s&code=c", nil)
	req.SetPathValue("routeName", "myroute")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadGateway {
		t.Errorf("status = %d, want %d; token without expires_in should be rejected", rr.Code, http.StatusBadGateway)
	}
	// Token must not be saved when expires_in is missing.
	if _, ok := tokenStore.Lookup("user", "myroute"); ok {
		t.Error("token must not be saved when expires_in is missing")
	}
}
