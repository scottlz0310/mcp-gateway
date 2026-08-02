package proxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

type mockServerTokenSource struct {
	token        string
	tokenErr     error
	refreshToken string
	refreshErr   error
	refreshCalls int
}

func (m *mockServerTokenSource) Token(context.Context) (string, error) {
	return m.token, m.tokenErr
}

func (m *mockServerTokenSource) RefreshAfter401(_ context.Context, _ string) (string, error) {
	m.refreshCalls++
	return m.refreshToken, m.refreshErr
}

// mockRefresher is a test double for UpstreamTokenRefresher.
type mockRefresher struct {
	after401Rec auth.UpstreamTokenRecord
	after401OK  bool
	freshRec    auth.UpstreamTokenRecord
	freshOK     bool
	calls401    int
}

func (m *mockRefresher) EnsureFreshToken(_ context.Context, _, _ string, rec auth.UpstreamTokenRecord) (auth.UpstreamTokenRecord, bool) {
	return m.freshRec, m.freshOK
}

func (m *mockRefresher) RefreshAfter401(_ context.Context, _, _ string) (auth.UpstreamTokenRecord, bool) {
	m.calls401++
	return m.after401Rec, m.after401OK
}

// rtFunc adapts a function to http.RoundTripper.
type rtFunc func(*http.Request) (*http.Response, error)

func (f rtFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// makeResponse constructs a minimal *http.Response with the given status code.
func makeResponse(code int) *http.Response {
	return &http.Response{
		StatusCode: code,
		Body:       http.NoBody,
		Header:     make(http.Header),
	}
}

func requestWithIdentity(identity string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/mcp/test", nil)
	ctx := context.WithValue(req.Context(), middleware.ContextKeyIdentity, identity)
	return req.WithContext(ctx)
}

// ── refreshingTransport unit tests ──────────────────────────────────────────

func TestRefreshingTransport_NonUnauthorizedPassthrough(t *testing.T) {
	callCount := 0
	base := rtFunc(func(_ *http.Request) (*http.Response, error) {
		callCount++
		return makeResponse(http.StatusOK), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: &mockRefresher{}},
	}

	resp, err := rt.RoundTrip(requestWithIdentity("alice"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
	if callCount != 1 {
		t.Errorf("base called %d times, want 1", callCount)
	}
}

func TestRefreshingTransport_EmptySubjectSkipsRefresh(t *testing.T) {
	mr := &mockRefresher{}
	base := rtFunc(func(_ *http.Request) (*http.Response, error) {
		return makeResponse(http.StatusUnauthorized), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: mr},
	}

	// Request without identity in context.
	req := httptest.NewRequest(http.MethodGet, "/mcp/test", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if mr.calls401 != 0 {
		t.Errorf("RefreshAfter401 called %d times, want 0", mr.calls401)
	}
}

func TestRefreshingTransport_RefreshFailedReturns401(t *testing.T) {
	mr := &mockRefresher{
		after401OK: false,
	}
	base := rtFunc(func(_ *http.Request) (*http.Response, error) {
		return makeResponse(http.StatusUnauthorized), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: mr},
	}

	resp, err := rt.RoundTrip(requestWithIdentity("alice"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
	if mr.calls401 != 1 {
		t.Errorf("RefreshAfter401 called %d times, want 1", mr.calls401)
	}
}

func TestRefreshingTransport_NonReplayableBodySkipsRetry(t *testing.T) {
	// When req.Body is set but GetBody is nil (non-replayable stream), retry
	// must not be attempted: the body has already been consumed by the first
	// RoundTrip, so a second RoundTrip would send an empty body.
	mr := &mockRefresher{
		after401OK:  true,
		after401Rec: auth.UpstreamTokenRecord{AccessToken: "new-tok"},
	}

	callCount := 0
	base := rtFunc(func(_ *http.Request) (*http.Response, error) {
		callCount++
		return makeResponse(http.StatusUnauthorized), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: mr},
	}

	req := requestWithIdentity("alice")
	// Attach a non-replayable body (GetBody == nil).
	req.Body = io.NopCloser(strings.NewReader(`{"method":"test"}`))
	req.ContentLength = 18
	// GetBody is intentionally nil (default for non-buffered readers).

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// 401 must be returned as-is; no retry.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d (non-replayable body: retry must be skipped)", resp.StatusCode, http.StatusUnauthorized)
	}
	if callCount != 1 {
		t.Errorf("base called %d times, want 1 (no retry for non-replayable body)", callCount)
	}
}

func TestRefreshingTransport_ReplayableBodyRetries(t *testing.T) {
	// When GetBody is set (replayable), retry must proceed and the body must be
	// rewound via GetBody so the second RoundTrip receives the original content.
	// The first RoundTrip consumes req.Body; without GetBody rewind the retry
	// would send an empty body and silently corrupt the upstream request.
	mr := &mockRefresher{
		after401OK:  true,
		after401Rec: auth.UpstreamTokenRecord{AccessToken: "new-tok"},
	}

	const bodyContent = `{"method":"test"}`
	var capturedRetryBody string
	callCount := 0
	base := rtFunc(func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			// Consume the body exactly as a real RoundTripper would.
			_, _ = io.ReadAll(req.Body)
			return makeResponse(http.StatusUnauthorized), nil
		}
		// On retry: body must have been rewound by GetBody().
		b, _ := io.ReadAll(req.Body)
		capturedRetryBody = string(b)
		return makeResponse(http.StatusOK), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: mr},
	}

	req := requestWithIdentity("alice")
	req.Body = io.NopCloser(strings.NewReader(bodyContent))
	req.ContentLength = int64(len(bodyContent))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(bodyContent)), nil
	}

	resp, err := rt.RoundTrip(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (replayable body: retry should succeed)", resp.StatusCode, http.StatusOK)
	}
	if callCount != 2 {
		t.Errorf("base called %d times, want 2 (initial + retry)", callCount)
	}
	if capturedRetryBody != bodyContent {
		t.Errorf("retry body = %q, want %q (body must be rewound for retry)", capturedRetryBody, bodyContent)
	}
}

func TestRefreshingTransport_RefreshSuccessRetries(t *testing.T) {
	mr := &mockRefresher{
		after401OK:  true,
		after401Rec: auth.UpstreamTokenRecord{AccessToken: "new-tok"},
	}

	var capturedAuth string
	callCount := 0
	base := rtFunc(func(req *http.Request) (*http.Response, error) {
		callCount++
		if callCount == 1 {
			return makeResponse(http.StatusUnauthorized), nil
		}
		capturedAuth = req.Header.Get("Authorization")
		return makeResponse(http.StatusOK), nil
	})

	rt := &refreshingTransport{
		base: base,
		opts: &UpstreamOAuthOptions{RouteName: "myroute", Refresher: mr},
	}

	resp, err := rt.RoundTrip(requestWithIdentity("alice"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d (retry should succeed)", resp.StatusCode, http.StatusOK)
	}
	if callCount != 2 {
		t.Errorf("base called %d times, want 2 (initial + retry)", callCount)
	}
	if capturedAuth != "Bearer new-tok" {
		t.Errorf("retry Authorization = %q, want %q", capturedAuth, "Bearer new-tok")
	}
}

// ── NewHandler integration: proactive refresh ────────────────────────────────

func TestProxyUpstreamOAuthProactiveRefreshUpdatesToken(t *testing.T) {
	// EnsureFreshToken returns a newer token; proxy must inject it.
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("alice@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(2 * time.Minute), // within proactive window
	})

	mr := &mockRefresher{
		freshOK:  true,
		freshRec: auth.UpstreamTokenRecord{AccessToken: "refreshed-tok"},
	}

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
		Refresher:  mr,
	})

	r := requestWithContext("alice@example.com", "gateway-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotAuth != "Bearer refreshed-tok" {
		t.Errorf("Authorization = %q, want %q", gotAuth, "Bearer refreshed-tok")
	}
}

func TestProxyUpstreamOAuthProactiveRefreshFailureForwardsWithoutAuth(t *testing.T) {
	// EnsureFreshToken returns ok=false (permanent failure); proxy forwards
	// the request without an Authorization header.
	var gotAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("alice@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(2 * time.Minute),
	})

	mr := &mockRefresher{
		freshOK: false, // permanent failure
	}

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
		Refresher:  mr,
	})

	r := requestWithContext("alice@example.com", "gateway-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty (proactive refresh failed)", gotAuth)
	}
}

func TestProxyUpstreamOAuthRefresherWith401TransparentRetry(t *testing.T) {
	// End-to-end: upstream returns 401 first, then 200 after retry.
	// refreshingTransport intercepts the 401, refreshes, and retries.
	callCount := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		if callCount == 1 {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("bob@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(time.Hour),
	})

	mr := &mockRefresher{
		after401OK:  true,
		after401Rec: auth.UpstreamTokenRecord{AccessToken: "refreshed-tok"},
		freshOK:     true, // EnsureFreshToken returns existing token unchanged
	}
	// Make EnsureFreshToken return the existing record (not near expiry).
	mr.freshRec = auth.UpstreamTokenRecord{
		AccessToken:  "old-tok",
		RefreshToken: "ref",
		ExpiresAt:    time.Now().Add(time.Hour),
	}

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
		Refresher:  mr,
	})

	r := requestWithContext("bob@example.com", "gateway-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusOK {
		t.Errorf("final status = %d, want %d (transparent retry should succeed)", w.Code, http.StatusOK)
	}
	if callCount != 2 {
		t.Errorf("upstream called %d times, want 2 (initial 401 + retry)", callCount)
	}
}

func TestProxyUpstreamOAuthWith401WhenRefresherNil(t *testing.T) {
	// Backward compat: when Refresher is nil, 401 still deletes the stale token.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	tokenStore := auth.NewMemUpstreamTokenStore()
	_ = tokenStore.Save("carol@example.com", "myroute", auth.UpstreamTokenRecord{
		AccessToken: "stale-tok",
		ExpiresAt:   time.Now().Add(time.Hour),
	})

	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", &UpstreamOAuthOptions{
		TokenStore: tokenStore,
		RouteName:  "myroute",
		Refresher:  nil, // no refresher
	})

	r := requestWithContext("carol@example.com", "gateway-tok")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
	// Token must be deleted (#117 behavior preserved).
	if _, ok := tokenStore.Lookup("carol@example.com", "myroute"); ok {
		t.Error("expected stale token to be deleted when Refresher is nil")
	}
}

func TestProxyServerTokenSource(t *testing.T) {
	tests := []struct {
		name          string
		source        *mockServerTokenSource
		firstStatus   int
		wantStatus    int
		wantAuth      string
		wantCalls     int
		wantRefreshes int
	}{
		{
			name: "injects installation token", source: &mockServerTokenSource{token: "ghs_initial"},
			firstStatus: http.StatusOK, wantStatus: http.StatusOK, wantAuth: "Bearer ghs_initial", wantCalls: 1,
		},
		{
			name: "refreshes after 401", source: &mockServerTokenSource{token: "ghs_stale", refreshToken: "ghs_fresh"},
			firstStatus: http.StatusUnauthorized, wantStatus: http.StatusOK, wantAuth: "Bearer ghs_fresh", wantCalls: 2, wantRefreshes: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			lastAuth := ""
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				lastAuth = r.Header.Get("Authorization")
				if calls == 1 && tt.firstStatus == http.StatusUnauthorized {
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL)
			h := NewHandler(u, &mockInvalidator{}, "", "", nil, WithServerTokenSource("github", tt.source))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, requestWithContext("alice", "gateway-token"))
			if w.Code != tt.wantStatus || calls != tt.wantCalls || lastAuth != tt.wantAuth || tt.source.refreshCalls != tt.wantRefreshes {
				t.Fatalf("status=%d calls=%d auth=%q refreshes=%d", w.Code, calls, lastAuth, tt.source.refreshCalls)
			}
		})
	}
}

func TestProxyServerTokenSourceFailsClosed(t *testing.T) {
	upstreamCalls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		upstreamCalls++
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := NewHandler(u, &mockInvalidator{}, "", "", nil, WithServerTokenSource("github", &mockServerTokenSource{
		tokenErr: errors.New("credential unavailable"),
	}))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "gateway-token"))
	if w.Code != http.StatusBadGateway || upstreamCalls != 0 || strings.Contains(w.Body.String(), "credential unavailable") {
		t.Fatalf("status=%d calls=%d body=%q", w.Code, upstreamCalls, w.Body.String())
	}
}
