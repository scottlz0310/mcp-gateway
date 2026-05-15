package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

// newDelegatedTestHandler builds a Handler wired to a Mock provider with
// GitHub-style rotation enabled, so EnsureFreshAccessTokenForSubject exercises
// the same tryGitHubRotation path used in production.
func newDelegatedTestHandler(t *testing.T, p provider.Provider, leeway time.Duration) *Handler {
	t.Helper()
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		GitHubRefreshEnabled: true,
		GitHubRefreshLeeway:  leeway,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// TestEnsureFreshAccessTokenForSubject_CachedOutsideLeeway verifies that a
// token whose provider expiry is well past the leeway window is returned
// as-is without invoking the rotation path.
func TestEnsureFreshAccessTokenForSubject_CachedOutsideLeeway(t *testing.T) {
	var refreshCalls int32
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			atomic.AddInt32(&refreshCalls, 1)
			return provider.TokenResponse{AccessToken: "should-not-be-used"}, nil
		},
	}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	h.store.CacheToken("tok-cached", "alice", "http://localhost:8080/mcp")
	farFuture := time.Now().Add(1 * time.Hour)
	h.store.RecordProviderRefresh("tok-cached", "refresh-secret", farFuture)

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "tok-cached" {
		t.Errorf("access token: got %q want %q", res.AccessToken, "tok-cached")
	}
	if res.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected non-zero ProviderAccessExpiry")
	}
	if got := atomic.LoadInt32(&refreshCalls); got != 0 {
		t.Errorf("RefreshToken called %d times, want 0", got)
	}
}

// TestEnsureFreshAccessTokenForSubject_RotationSucceeds verifies that when
// the cached token is inside the leeway window and the provider returns a
// fresh token, the rotated value is surfaced (with its new expiry).
func TestEnsureFreshAccessTokenForSubject_RotationSucceeds(t *testing.T) {
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{
				AccessToken:          "tok-rotated",
				RefreshToken:         "refresh-new",
				AccessTokenExpiresIn: 8 * time.Hour,
				Scopes:               []string{"repo", "user"},
			}, nil
		},
	}
	h := newDelegatedTestHandler(t, p, 5*time.Minute)
	h.store.CacheToken("tok-stale", "alice", "http://localhost:8080/mcp")
	// Put the cached expiry inside the leeway window so rotation triggers.
	soon := time.Now().Add(30 * time.Second)
	h.store.RecordProviderRefresh("tok-stale", "refresh-old", soon)

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "tok-rotated" {
		t.Errorf("access token: got %q want %q", res.AccessToken, "tok-rotated")
	}
	if res.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected non-zero ProviderAccessExpiry on rotated record")
	}
	if time.Until(res.ProviderAccessExpiry) < 1*time.Hour {
		t.Errorf("rotated expiry too close: %v", res.ProviderAccessExpiry)
	}
}

// TestEnsureFreshAccessTokenForSubject_RotationFailedInLeeway verifies that
// when the cached token is inside the leeway window AND rotation fails (here
// with a transient upstream error), the handler returns ErrRotationFailed
// rather than handing back a near-dead cached token.
func TestEnsureFreshAccessTokenForSubject_RotationFailedInLeeway(t *testing.T) {
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, &provider.UpstreamError{Err: errors.New("502 from github")}
		},
	}
	h := newDelegatedTestHandler(t, p, 5*time.Minute)
	h.store.CacheToken("tok-dying", "alice", "http://localhost:8080/mcp")
	soon := time.Now().Add(30 * time.Second)
	h.store.RecordProviderRefresh("tok-dying", "refresh-old", soon)

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("err: got %v want ErrRotationFailed", err)
	}
}

// TestEnsureFreshAccessTokenForSubject_RotationPermanentClearsMetadata
// verifies that a permanent provider failure clears the cached refresh
// metadata AND surfaces ErrRotationFailed (the cached access token is still
// inside the leeway window, so we must not return it as a usable bearer).
func TestEnsureFreshAccessTokenForSubject_RotationPermanentClearsMetadata(t *testing.T) {
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, errors.New("bad_refresh_token")
		},
	}
	h := newDelegatedTestHandler(t, p, 5*time.Minute)
	h.store.CacheToken("tok-poisoned", "alice", "http://localhost:8080/mcp")
	soon := time.Now().Add(30 * time.Second)
	h.store.RecordProviderRefresh("tok-poisoned", "refresh-bad", soon)

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("err: got %v want ErrRotationFailed", err)
	}
	// Metadata should now be cleared (permanent path calls ClearProviderRefresh).
	rec, ok := h.store.LookupToken("tok-poisoned")
	if !ok {
		t.Fatal("token entry should still exist (only metadata is cleared)")
	}
	if rec.ProviderRefreshToken != "" || !rec.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected provider metadata cleared, got refresh=%q expiry=%v",
			rec.ProviderRefreshToken, rec.ProviderAccessExpiry)
	}
}

// TestEnsureFreshAccessTokenForSubject_SubjectNotFound verifies the 404 path.
func TestEnsureFreshAccessTokenForSubject_SubjectNotFound(t *testing.T) {
	p := &provider.Mock{NameValue: "github", ScopesValue: "repo"}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "ghost")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("err: got %v want ErrSubjectNotFound", err)
	}
}

// TestEnsureFreshAccessTokenForSubject_NoRotationMetadataReturnsCached
// verifies that a token without rotation metadata (e.g. classic non-expiring
// PAT) is returned as-is. This is the "lenient" branch: we only fail when we
// know the cached token is near death.
func TestEnsureFreshAccessTokenForSubject_NoRotationMetadataReturnsCached(t *testing.T) {
	p := &provider.Mock{NameValue: "github", ScopesValue: "repo"}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	h.store.CacheToken("tok-pat", "alice", "http://localhost:8080/mcp")
	// No RecordProviderRefresh: rotation metadata is absent.

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "tok-pat" {
		t.Errorf("access token: got %q want %q", res.AccessToken, "tok-pat")
	}
	if !res.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected zero ProviderAccessExpiry for non-rotating PAT, got %v",
			res.ProviderAccessExpiry)
	}
}
