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

// TestRunGitHubRotation_NoOpWhenSecondReadOutsideLeeway verifies that the
// singleflight leader signals noOp (not failure) when the authoritative
// re-read inside runGitHubRotation shows the cached expiry has already
// moved outside the leeway window. This simulates the race where a prior
// leader on the same key has just completed a successful rotation and
// updated the original entry's metadata.
func TestRunGitHubRotation_NoOpWhenSecondReadOutsideLeeway(t *testing.T) {
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			t.Fatal("RefreshToken should not be called when re-read shows expiry outside leeway")
			return provider.TokenResponse{}, nil
		},
	}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	h.store.CacheToken("tok-rotated", "alice", "")
	farFuture := time.Now().Add(1 * time.Hour)
	h.store.RecordProviderRefresh("tok-rotated", "refresh-secret", farFuture)

	res := h.runGitHubRotation(context.Background(), "tok-rotated", "")
	if res.ok {
		t.Errorf("expected ok=false (no rotation produced), got ok=true")
	}
	if !res.noOp {
		t.Errorf("expected noOp=true (concurrent success / outside leeway), got noOp=false")
	}
}

// TestRunGitHubRotation_NoOpWhenCacheMiss verifies that runGitHubRotation
// reports noOp=true when the cache entry has disappeared between the outer
// precondition check and the inner re-read. The entry is gone, so the caller
// has nothing to rotate; this is not a rotation failure.
func TestRunGitHubRotation_NoOpWhenCacheMiss(t *testing.T) {
	p := &provider.Mock{NameValue: "github", ScopesValue: "repo"}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	// Deliberately no CacheToken — Lookup will return ok=false inside
	// runGitHubRotation.
	res := h.runGitHubRotation(context.Background(), "missing-tok", "")
	if res.ok {
		t.Errorf("expected ok=false, got ok=true")
	}
	if !res.noOp {
		t.Errorf("expected noOp=true when cache entry is missing, got noOp=false")
	}
}

// TestLatestBySubject_PrunesStaleSubjectIndexEntries verifies that entries
// whose authoritative TokenStore lookup fails are removed from the in-memory
// subject index, so stale bearer strings do not remain reachable until the
// index TTL expires.
func TestLatestBySubject_PrunesStaleSubjectIndexEntries(t *testing.T) {
	p := &provider.Mock{NameValue: "github", ScopesValue: "repo"}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	// Live entry: present in both the token store and the subject index.
	h.store.CacheToken("tok-live", "alice", "")
	// Stale entry: pushed directly into the subject index but never
	// stored in the underlying token store, so Lookup returns false.
	h.store.indexSubjectToken("alice", "tok-stale", time.Now().Add(1*time.Hour))

	gotToken, _, ok := h.store.LatestBySubject("alice")
	if !ok {
		t.Fatalf("LatestBySubject ok=false, want true")
	}
	if gotToken != "tok-live" {
		t.Errorf("returned token: got %q want %q", gotToken, "tok-live")
	}
	// The stale entry must have been pruned from the index.
	h.store.subjectIndexMu.Lock()
	entries := h.store.subjectIndex["alice"]
	h.store.subjectIndexMu.Unlock()
	for _, e := range entries {
		if e.rawToken == "tok-stale" {
			t.Errorf("expected stale entry %q to be pruned from subjectIndex, still present", e.rawToken)
		}
	}
}

// TestLatestBySubject_PrunesSubjectMismatchEntries verifies that an index
// entry whose authoritative record carries a different Subject is pruned —
// this defense-in-depth path must not leave another subject's bearer
// reachable through the index.
func TestLatestBySubject_PrunesSubjectMismatchEntries(t *testing.T) {
	p := &provider.Mock{NameValue: "github", ScopesValue: "repo"}
	h := newDelegatedTestHandler(t, p, 1*time.Minute)
	// "tok-bob" was originally indexed under alice but the authoritative
	// record now belongs to bob. Simulate by writing the token record as
	// bob and then forging an alice index entry.
	h.store.CacheToken("tok-bob", "bob", "")
	h.store.indexSubjectToken("alice", "tok-bob", time.Now().Add(1*time.Hour))
	h.store.CacheToken("tok-alice", "alice", "")

	gotToken, _, ok := h.store.LatestBySubject("alice")
	if !ok {
		t.Fatalf("LatestBySubject ok=false, want true")
	}
	if gotToken != "tok-alice" {
		t.Errorf("returned token: got %q want %q", gotToken, "tok-alice")
	}
	h.store.subjectIndexMu.Lock()
	entries := h.store.subjectIndex["alice"]
	h.store.subjectIndexMu.Unlock()
	for _, e := range entries {
		if e.rawToken == "tok-bob" {
			t.Errorf("expected subject-mismatch entry %q to be pruned, still present", e.rawToken)
		}
	}
}

// TestEnsureFreshAccessTokenForSubject_PermanentFailureLenientBranchReturnsError
// verifies Gap 2 fix: after a permanent rotation failure, a *subsequent* call
// to EnsureFreshAccessTokenForSubject must never return the (now-dead) cached
// bearer. MarkRotationPermanentlyFailed removes the token from the subject
// index (via removeSubjectIndexEntry) and persists a RotationPermanentlyFailed
// flag to the token store so ValidateToken cannot re-seed the subject index
// after a restart. The second call finds no entry for the subject and returns
// ErrSubjectNotFound — not the dead bearer.
func TestEnsureFreshAccessTokenForSubject_PermanentFailureLenientBranchReturnsError(t *testing.T) {
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, errors.New("bad_refresh_token")
		},
	}
	h := newDelegatedTestHandler(t, p, 5*time.Minute)
	h.store.CacheToken("tok-dead", "alice", "http://localhost:8080/mcp")
	soon := time.Now().Add(30 * time.Second)
	h.store.RecordProviderRefresh("tok-dead", "refresh-bad", soon)

	// First call: token is inside leeway → rotation attempted → permanent
	// failure → token evicted from store + subject index, flag set.
	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("first call: err=%v want ErrRotationFailed", err)
	}

	// Second call: MarkRotationPermanentlyFailed removed token from the subject
	// index → LatestBySubject finds no entry for "alice" → ErrSubjectNotFound.
	// The dead bearer is never returned (Gap 2 fix, Thread 1 durability fix).
	_, err = h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("second call (subject index cleared): err=%v want ErrSubjectNotFound (Gap 2 + Thread 1 durability fix)", err)
	}
}

// TestRotationPermanentlyFailedSurvivesRestart verifies the restart-durability
// fix for Thread 1 of Issue #77: after MarkRotationPermanentlyFailed is called,
// a simulated restart (new Handler with the same TokenStorePath) must NOT
// re-seed the subject index for the permanently-failed token.
//
// Without the fix, ValidateToken would call RefreshSubjectIndex on the first
// cache hit after restart, and EnsureFreshAccessTokenForSubject could then
// return the dead bearer via the lenient branch.
func TestRotationPermanentlyFailedSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	storePath := dir + "/tokens.json"

	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, errors.New("bad_refresh_token")
		},
	}

	cfg := Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		TokenStorePath:       storePath,
		GitHubRefreshEnabled: true,
		GitHubRefreshLeeway:  5 * time.Minute,
	}

	// ── first process ────────────────────────────────────────────────────────
	h1, err := NewHandler(cfg, p)
	if err != nil {
		t.Fatalf("NewHandler (first process): %v", err)
	}
	t.Cleanup(func() { _ = h1.Close() })

	// Seed: cache token + set provider refresh metadata so rotation is attempted.
	h1.store.CacheToken("tok-dead", "alice", "http://localhost:8080/mcp")
	soon := time.Now().Add(30 * time.Second)
	h1.store.RecordProviderRefresh("tok-dead", "refresh-bad", soon)

	// Trigger permanent failure via EnsureFreshAccessTokenForSubject.
	_, ferr := h1.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(ferr, ErrRotationFailed) {
		t.Fatalf("first process EnsureFresh: err=%v want ErrRotationFailed", ferr)
	}

	// Confirm the file store has the flag persisted before simulating restart.
	rec, ok := h1.store.tokens.Lookup("tok-dead")
	if !ok {
		t.Fatal("pre-restart: token should still be in the file store (not evicted)")
	}
	if !rec.RotationPermanentlyFailed {
		t.Fatal("pre-restart: RotationPermanentlyFailed flag should be persisted to file store")
	}

	// ── simulate restart: new Handler backed by the same file ─────────────────
	if err := h1.Close(); err != nil {
		t.Fatalf("h1.Close before restart: %v", err)
	}
	h2, err := NewHandler(cfg, p)
	if err != nil {
		t.Fatalf("NewHandler (restart): %v", err)
	}
	t.Cleanup(func() { _ = h2.Close() })
	defer h2.store.Stop()

	// ValidateToken must still authenticate the user (token is still valid as
	// a gateway bearer) but must NOT re-seed the subject index.
	subj, _, valErr := h2.ValidateToken(context.Background(), "tok-dead", "http://localhost:8080/mcp")
	if valErr != nil {
		t.Fatalf("ValidateToken after restart: %v", valErr)
	}
	if subj != "alice" {
		t.Errorf("ValidateToken after restart: subject got %q, want alice", subj)
	}

	// EnsureFreshAccessTokenForSubject must return ErrSubjectNotFound because
	// the subject index was NOT re-seeded by the ValidateToken call above.
	_, err = h2.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("EnsureFresh after restart: err=%v want ErrSubjectNotFound (dead bearer must not be returned)", err)
	}
}
