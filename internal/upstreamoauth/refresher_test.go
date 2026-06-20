package upstreamoauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

// makeRefresher constructs a Refresher backed by the given token endpoint server.
func makeRefresher(t *testing.T, clientRecords map[string]upstreamoauth.ClientRecord, tokenStore auth.UpstreamTokenStore, httpClient *http.Client) *upstreamoauth.Refresher {
	t.Helper()
	cs := &testClientStore{records: clientRecords}
	mgr := upstreamoauth.NewManager(cs, "http://localhost:8080")
	return upstreamoauth.NewRefresher(tokenStore, mgr, httpClient)
}

// futureExpiry returns a time well beyond the proactive window.
func futureExpiry() time.Time {
	return time.Now().Add(10 * time.Minute)
}

// nearExpiry returns a time within the proactive window (5 min default).
func nearExpiry() time.Time {
	return time.Now().Add(2 * time.Minute)
}

func TestEnsureFreshToken_NoExpirySkipsRefresh(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	refresher := makeRefresher(t, nil, store, nil)

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "tok",
		RefreshToken: "ref",
		// ExpiresAt zero = permanent / unknown
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "route", rec)
	if !ok {
		t.Fatal("expected ok=true when ExpiresAt is zero")
	}
	if got.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestEnsureFreshToken_FutureExpirySkipsRefresh(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	refresher := makeRefresher(t, nil, store, nil)

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "tok",
		RefreshToken: "ref",
		ExpiresAt:    futureExpiry(),
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "route", rec)
	if !ok {
		t.Fatal("expected ok=true when token is not near expiry")
	}
	if got.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestEnsureFreshToken_NoRefreshTokenSkipsRefresh(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	refresher := makeRefresher(t, nil, store, nil)

	rec := auth.UpstreamTokenRecord{
		AccessToken: "tok",
		ExpiresAt:   nearExpiry(),
		// RefreshToken empty
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "route", rec)
	if !ok {
		t.Fatal("expected ok=true when no refresh_token available")
	}
	if got.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestEnsureFreshToken_ProactiveRefreshSuccess(t *testing.T) {
	ts := makeTokenServer(t, map[string]any{
		"access_token":  "new-tok",
		"refresh_token": "new-ref",
		"expires_in":    3600,
	})
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			Issuer:        "https://upstream.example.com",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
	if !ok {
		t.Fatal("expected ok=true on successful proactive refresh")
	}
	if got.AccessToken != "new-tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "new-tok")
	}
	if got.RefreshToken != "new-ref" {
		t.Errorf("RefreshToken = %q, want %q", got.RefreshToken, "new-ref")
	}

	// Token must be persisted.
	saved, ok2 := store.Lookup("user", "myroute")
	if !ok2 {
		t.Fatal("refreshed token must be saved in store")
	}
	if saved.AccessToken != "new-tok" {
		t.Errorf("saved AccessToken = %q, want %q", saved.AccessToken, "new-tok")
	}
}

func TestEnsureFreshToken_ProactiveRefreshPreservesOldRefreshToken(t *testing.T) {
	// AS does not rotate the refresh_token (omits it in response).
	ts := makeTokenServer(t, map[string]any{
		"access_token": "new-tok",
		"expires_in":   3600,
		// refresh_token intentionally absent
	})
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	const oldRefToken = "old-ref"
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: oldRefToken,
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: oldRefToken,
		ExpiresAt:    nearExpiry(),
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
	if !ok {
		t.Fatal("expected ok=true")
	}
	if got.RefreshToken != oldRefToken {
		t.Errorf("RefreshToken = %q, want old token %q (AS did not rotate)", got.RefreshToken, oldRefToken)
	}
}

func TestEnsureFreshToken_PermanentFailureDeletesToken(t *testing.T) {
	// Token endpoint returns 401 = permanent failure (invalid refresh_token).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "bad-ref",
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "bad-ref",
		ExpiresAt:    nearExpiry(),
	}

	_, ok := refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
	if ok {
		t.Fatal("expected ok=false on permanent refresh failure")
	}

	// Token entry must be deleted from the store.
	if _, found := store.Lookup("user", "myroute"); found {
		t.Error("token must be deleted after permanent refresh failure")
	}
}

func TestEnsureFreshToken_TransientFailureKeepsToken(t *testing.T) {
	// 429 Too Many Requests = transient.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
	if !ok {
		t.Fatal("expected ok=true on transient failure (keep existing token)")
	}
	if got.AccessToken != "old-tok" {
		t.Errorf("expected existing token %q, got %q", "old-tok", got.AccessToken)
	}

	// Token must still be in the store.
	if _, found := store.Lookup("user", "myroute"); !found {
		t.Error("token must not be deleted on transient failure")
	}
}

func TestEnsureFreshToken_NoClientRegistrationKeepsToken(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "tok",
		RefreshToken: "ref",
		ExpiresAt:    nearExpiry(),
	})

	// No client record registered.
	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{}, store, nil)

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "tok",
		RefreshToken: "ref",
		ExpiresAt:    nearExpiry(),
	}

	got, ok := refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
	if !ok {
		t.Fatal("expected ok=true when no client registration (transient: cannot refresh)")
	}
	if got.AccessToken != "tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "tok")
	}
}

func TestRefreshAfter401_NoTokenInStore(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	refresher := makeRefresher(t, nil, store, nil)

	_, ok := refresher.RefreshAfter401(context.Background(), "user", "myroute")
	if ok {
		t.Fatal("expected ok=false when no token in store")
	}
}

func TestRefreshAfter401_NoRefreshToken(t *testing.T) {
	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "tok",
		ExpiresAt:   nearExpiry(),
		// no RefreshToken
	})

	refresher := makeRefresher(t, nil, store, nil)

	_, ok := refresher.RefreshAfter401(context.Background(), "user", "myroute")
	if ok {
		t.Fatal("expected ok=false when no refresh_token available")
	}

	// Token entry must be deleted (no refresh possible, force re-auth).
	if _, found := store.Lookup("user", "myroute"); found {
		t.Error("token must be deleted when no refresh_token is available")
	}
}

func TestRefreshAfter401_Success(t *testing.T) {
	ts := makeTokenServer(t, map[string]any{
		"access_token":  "new-tok",
		"refresh_token": "new-ref",
		"expires_in":    3600,
	})
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    time.Now().Add(-time.Minute), // already expired
	})

	// Manually insert an already-expired record; Lookup would reject it, but
	// RefreshAfter401 reads it to get the refresh_token before it expires in store.
	// Re-insert with valid expiry so Lookup succeeds for the refresh_token read.
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    futureExpiry(), // keep in store long enough for test
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			Issuer:        "https://upstream.example.com",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "client-id",
			ClientSecret:  "client-secret",
		},
	}, store, ts.Client())

	got, ok := refresher.RefreshAfter401(context.Background(), "user", "myroute")
	if !ok {
		t.Fatal("expected ok=true on successful 401 refresh")
	}
	if got.AccessToken != "new-tok" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "new-tok")
	}
}

func TestRefreshAfter401_PermanentFailureDeletesToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden) // 403 = permanent
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "tok",
		RefreshToken: "bad-ref",
		ExpiresAt:    futureExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	_, ok := refresher.RefreshAfter401(context.Background(), "user", "myroute")
	if ok {
		t.Fatal("expected ok=false on permanent failure")
	}
	if _, found := store.Lookup("user", "myroute"); found {
		t.Error("token must be deleted after permanent 401 refresh failure")
	}
}

func TestRefreshEndpointSendsGrantTypeRefreshToken(t *testing.T) {
	var capturedForm map[string]string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		capturedForm = map[string]string{
			"grant_type":    r.FormValue("grant_type"),
			"refresh_token": r.FormValue("refresh_token"),
			"client_id":     r.FormValue("client_id"),
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-tok",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "my-refresh-token",
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "my-client-id",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "my-refresh-token",
		ExpiresAt:    nearExpiry(),
	}

	_, _ = refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)

	if capturedForm["grant_type"] != "refresh_token" {
		t.Errorf("grant_type = %q, want %q", capturedForm["grant_type"], "refresh_token")
	}
	if capturedForm["refresh_token"] != "my-refresh-token" {
		t.Errorf("refresh_token = %q, want %q", capturedForm["refresh_token"], "my-refresh-token")
	}
	if capturedForm["client_id"] != "my-client-id" {
		t.Errorf("client_id = %q, want %q", capturedForm["client_id"], "my-client-id")
	}
}

func TestEnsureFreshToken_ConcurrentCallsCoalesceToOneEndpointRequest(t *testing.T) {
	// Verifies the singleflight invariant: N concurrent EnsureFreshToken calls
	// for the same (subject, routeName) result in exactly 1 token endpoint request.
	const goroutines = 10

	var endpointCalls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		endpointCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-tok",
			"refresh_token": "new-ref",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	rec := auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    nearExpiry(),
	}

	var wg sync.WaitGroup
	results := make([]auth.UpstreamTokenRecord, goroutines)
	oks := make([]bool, goroutines)

	wg.Add(goroutines)
	var start sync.WaitGroup
	start.Add(1)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			start.Wait() // all goroutines start simultaneously
			results[idx], oks[idx] = refresher.EnsureFreshToken(context.Background(), "user", "myroute", rec)
		}(i)
	}
	start.Done() // release all goroutines
	wg.Wait()

	calls := endpointCalls.Load()
	if calls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (singleflight coalescing)", calls)
	}
	for i, ok := range oks {
		if !ok {
			t.Errorf("goroutine %d: expected ok=true", i)
		}
		if results[i].AccessToken != "new-tok" {
			t.Errorf("goroutine %d: AccessToken = %q, want %q", i, results[i].AccessToken, "new-tok")
		}
	}
}

func TestRefreshAfter401_ConcurrentCallsCoalesceToOneEndpointRequest(t *testing.T) {
	// Verifies the singleflight invariant for RefreshAfter401:
	// N concurrent calls for the same key result in exactly 1 endpoint request.
	const goroutines = 10

	var endpointCalls atomic.Int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		endpointCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  "new-tok",
			"refresh_token": "new-ref",
			"expires_in":    3600,
		})
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "old-ref",
		ExpiresAt:    futureExpiry(),
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	var wg sync.WaitGroup
	results := make([]auth.UpstreamTokenRecord, goroutines)
	oks := make([]bool, goroutines)

	wg.Add(goroutines)
	var start sync.WaitGroup
	start.Add(1)
	for i := range goroutines {
		go func(idx int) {
			defer wg.Done()
			start.Wait()
			results[idx], oks[idx] = refresher.RefreshAfter401(context.Background(), "user", "myroute")
		}(i)
	}
	start.Done()
	wg.Wait()

	calls := endpointCalls.Load()
	if calls != 1 {
		t.Errorf("token endpoint called %d times, want 1 (singleflight coalescing)", calls)
	}
	for i, ok := range oks {
		if !ok {
			t.Errorf("goroutine %d: expected ok=true", i)
		}
		if results[i].AccessToken != "new-tok" {
			t.Errorf("goroutine %d: AccessToken = %q, want %q", i, results[i].AccessToken, "new-tok")
		}
	}
}

func TestRefreshAfter401_ExpiredAccessTokenUsesRefreshToken(t *testing.T) {
	// access token が期限切れでも refresh_token があれば更新できることを確認する。
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "refresh_token" || r.FormValue("refresh_token") != "valid-ref" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "new-tok",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	store := auth.NewMemUpstreamTokenStore()
	// access token は既に期限切れ、refresh_token は有効
	_ = store.Save("user", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "expired-tok",
		RefreshToken: "valid-ref",
		ExpiresAt:    time.Now().Add(-time.Minute), // 1 分前に期限切れ
	})

	refresher := makeRefresher(t, map[string]upstreamoauth.ClientRecord{
		"myroute": {
			RouteName:     "myroute",
			TokenEndpoint: ts.URL + "/token",
			ClientID:      "cid",
		},
	}, store, ts.Client())

	rec, ok := refresher.RefreshAfter401(context.Background(), "user", "myroute")
	if !ok {
		t.Fatal("expected ok=true: expired access token should not prevent refresh via LookupForRefresh")
	}
	if rec.AccessToken != "new-tok" {
		t.Errorf("AccessToken = %q, want %q", rec.AccessToken, "new-tok")
	}
}
