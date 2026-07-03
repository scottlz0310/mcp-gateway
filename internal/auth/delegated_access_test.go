package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

// TestEnsureFreshAccessTokenForSubject_GhuTokenRotation verifies that
// tryGitHubRotation works correctly with GitHub Apps user-to-server tokens
// (ghu_ prefix) and their corresponding refresh tokens (ghr_ prefix).
// This is the primary expiring-token scenario for GitHub Apps.
func TestEnsureFreshAccessTokenForSubject_GhuTokenRotation(t *testing.T) {
	var observedRefreshToken string
	p := &provider.Mock{
		NameValue:   "github",
		ScopesValue: "repo,user",
		RefreshTokenFunc: func(_ context.Context, rt string) (provider.TokenResponse, error) {
			observedRefreshToken = rt
			return provider.TokenResponse{
				AccessToken:          "ghu_newaccess",
				RefreshToken:         "ghr_newrefresh",
				AccessTokenExpiresIn: 8 * time.Hour,
				Scopes:               []string{"repo", "user"},
			}, nil
		},
	}
	h := newDelegatedTestHandler(t, p, 5*time.Minute)
	// Seed a GitHub Apps ghu_ access token inside the leeway window.
	h.store.CacheToken("ghu_staleaccess", "alice", "http://localhost:8080/mcp")
	soon := time.Now().Add(30 * time.Second)
	h.store.RecordProviderRefresh("ghu_staleaccess", "ghr_oldrefresh", soon)

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "ghu_newaccess" {
		t.Errorf("access token: got %q want %q", res.AccessToken, "ghu_newaccess")
	}
	if observedRefreshToken != "ghr_oldrefresh" {
		t.Errorf("RefreshToken called with %q, want %q", observedRefreshToken, "ghr_oldrefresh")
	}
	if res.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected non-zero ProviderAccessExpiry on rotated record")
	}
	if time.Until(res.ProviderAccessExpiry) < 1*time.Hour {
		t.Errorf("rotated expiry too close: %v", res.ProviderAccessExpiry)
	}
	// The new refresh token must be persisted so subsequent rotations work.
	rec, ok := h.store.LookupToken("ghu_newaccess")
	if !ok {
		t.Fatal("rotated token not found in store")
	}
	if rec.ProviderRefreshToken != "ghr_newrefresh" {
		t.Errorf("new refresh token: got %q want %q", rec.ProviderRefreshToken, "ghr_newrefresh")
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

// newDelegatedBuiltinTestHandler builds a builtin-mode Handler (gateway issues
// its own RS256 JWTs; the Mock provider's Name() is "builtin") for exercising
// EnsureFreshAccessTokenForSubject's builtin branch. ghExchangeAccessToken is
// the GitHub access token ExchangeCode returns during the OAuth callback.
func newDelegatedBuiltinTestHandler(t *testing.T, ghExchangeAccessToken string) *Handler {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &provider.Mock{
		NameValue:     "builtin",
		ClientIDValue: "builtin-client-id",
		ScopesValue:   "read:user,user:email",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghExchangeAccessToken}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:        "http://localhost:8080",
		SessionTTL:     10 * time.Minute,
		CacheTTL:       5 * time.Minute,
		ExpiresIn:      90 * 24 * time.Hour,
		OIDCPrivateKey: key,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

// TestEnsureFreshAccessTokenForSubject_BuiltinReturnsProviderTokenNotJWT is
// the direct regression test for scottlz0310/mcp-gateway#188: in builtin
// mode, EnsureFreshAccessTokenForSubject must return the GitHub access token
// recorded at token-exchange time, never the gateway-issued JWT the client
// was handed.
func TestEnsureFreshAccessTokenForSubject_BuiltinReturnsProviderTokenNotJWT(t *testing.T) {
	const ghAccessToken = "gho_realgithubtoken"
	h := newDelegatedBuiltinTestHandler(t, ghAccessToken)
	_, jwt := runBuiltinFullFlow(t, h, "alice")
	if jwt == "" {
		t.Fatal("runBuiltinFullFlow: empty access_token in token response")
	}

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != ghAccessToken {
		t.Errorf("access token: got %q, want provider token %q", res.AccessToken, ghAccessToken)
	}
	if res.AccessToken == jwt {
		t.Fatal("regression: EnsureFreshAccessTokenForSubject leaked the gateway JWT instead of the GitHub access token")
	}
}

// TestEnsureFreshAccessTokenForSubject_BuiltinLegacyRecordWithoutProviderToken
// verifies the safe-fallback behavior for a JWT cached before this fix existed
// (ProviderAccessToken empty): EnsureFreshAccessTokenForSubject must return
// ErrSubjectNotFound (forcing re-authentication) rather than falling through
// to the non-builtin logic, which would otherwise hand back the raw JWT.
func TestEnsureFreshAccessTokenForSubject_BuiltinLegacyRecordWithoutProviderToken(t *testing.T) {
	h := newDelegatedBuiltinTestHandler(t, "gho_unused")
	h.store.CacheToken("legacy-jwt-no-provider-token", "bob", "http://localhost:8080")

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "bob")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("err: got %v, want ErrSubjectNotFound (force re-auth for pre-fix JWTs)", err)
	}
}

// ── builtin-mode rotation (scottlz0310/mcp-gateway#190) ─────────────────────

// newDelegatedBuiltinRotationTestHandler builds a builtin-mode Handler with
// GitHub refresh rotation enabled, wired to a Mock provider whose
// ExchangeCode issues an expiring GitHub token (RefreshToken +
// AccessTokenExpiresIn) and whose RefreshToken is refreshFunc. Tests drive
// the full OAuth flow via runBuiltinFullFlow so that the resulting
// TokenRecord carries real provider refresh metadata exactly as production
// tokenAuthCode would populate it, then exercise
// EnsureFreshAccessTokenForSubject's builtin rotation path against it.
func newDelegatedBuiltinRotationTestHandler(t *testing.T, exchangeAccessToken, exchangeRefreshToken string, exchangeExpiresIn time.Duration, refreshFunc func(context.Context, string) (provider.TokenResponse, error)) *Handler {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	p := &provider.Mock{
		NameValue:     "builtin",
		ClientIDValue: "builtin-client-id",
		ScopesValue:   "read:user,user:email",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{
				AccessToken:          exchangeAccessToken,
				RefreshToken:         exchangeRefreshToken,
				AccessTokenExpiresIn: exchangeExpiresIn,
			}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
		RefreshTokenFunc: refreshFunc,
	}
	h, err := NewHandler(Config{
		BaseURL:              "http://localhost:8080",
		SessionTTL:           10 * time.Minute,
		CacheTTL:             5 * time.Minute,
		ExpiresIn:            90 * 24 * time.Hour,
		OIDCPrivateKey:       key,
		GitHubRefreshEnabled: true,
		GitHubRefreshLeeway:  5 * time.Minute,
	}, p)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	return h
}

func runBuiltinGatewayRefresh(t *testing.T, h *Handler, refreshToken string) map[string]any {
	t.Helper()
	body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	h.Token(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway refresh: got %d; body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode gateway refresh response: %v", err)
	}
	return response
}

// TestEnsureFreshAccessTokenForSubject_BuiltinRotationSucceeds verifies that
// builtin-mode rotation refreshes the GitHub access token in place — the
// gateway JWT's TokenRecord.ProviderAccessToken is updated — while the JWT
// itself (the TokenStore cache key and the value the client holds) stays
// valid and unchanged.
func TestEnsureFreshAccessTokenForSubject_BuiltinRotationSucceeds(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_original", "ghr_original", 30*time.Second,
		func(_ context.Context, rt string) (provider.TokenResponse, error) {
			if rt != "ghr_original" {
				t.Errorf("RefreshToken called with %q, want %q", rt, "ghr_original")
			}
			return provider.TokenResponse{
				AccessToken:          "gho_rotated",
				RefreshToken:         "ghr_rotated",
				AccessTokenExpiresIn: 8 * time.Hour,
			}, nil
		})
	_, jwt := runBuiltinFullFlow(t, h, "alice")
	if jwt == "" {
		t.Fatal("runBuiltinFullFlow: empty access_token in token response")
	}

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "gho_rotated" {
		t.Errorf("access token: got %q, want rotated provider token %q", res.AccessToken, "gho_rotated")
	}
	if time.Until(res.ProviderAccessExpiry) < 1*time.Hour {
		t.Errorf("rotated expiry too close: %v", res.ProviderAccessExpiry)
	}

	// The cache key (JWT) must be unchanged: the client-facing token from the
	// OAuth flow is still valid and resolves to the same subject.
	sub, rotated, err := h.ValidateToken(context.Background(), jwt, "")
	if err != nil {
		t.Fatalf("ValidateToken(jwt) after builtin rotation: %v", err)
	}
	if sub != "alice" {
		t.Errorf("ValidateToken subject: got %q, want %q", sub, "alice")
	}
	if rotated != "" {
		t.Errorf("ValidateToken must never surface a rotated token to the client in builtin mode, got %q", rotated)
	}

	// The record under the JWT itself must reflect the rotated provider token.
	rec, ok := h.store.LookupToken(jwt)
	if !ok {
		t.Fatal("expected JWT record to still exist after rotation")
	}
	if rec.ProviderAccessToken != "gho_rotated" {
		t.Errorf("record.ProviderAccessToken: got %q, want %q", rec.ProviderAccessToken, "gho_rotated")
	}
	if rec.ProviderRefreshToken != "ghr_rotated" {
		t.Errorf("record.ProviderRefreshToken: got %q, want %q", rec.ProviderRefreshToken, "ghr_rotated")
	}
}

// TestEnsureFreshAccessTokenForSubject_BuiltinRotationSurvivesGatewayRefresh は、
// delegated rotation 後の provider token 世代が gateway refresh token にも反映され、
// gateway refresh grant 後の delegated access が失効済み世代へ戻らないことを検証する。
func TestEnsureFreshAccessTokenForSubject_BuiltinRotationSurvivesGatewayRefresh(t *testing.T) {
	var observedRefreshTokens []string
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_original", "ghr_original", 30*time.Second,
		func(_ context.Context, rt string) (provider.TokenResponse, error) {
			observedRefreshTokens = append(observedRefreshTokens, rt)
			switch rt {
			case "ghr_original":
				return provider.TokenResponse{
					AccessToken:          "gho_rotated_1",
					RefreshToken:         "ghr_rotated_1",
					AccessTokenExpiresIn: 30 * time.Second,
				}, nil
			case "ghr_rotated_1":
				return provider.TokenResponse{
					AccessToken:          "gho_rotated_2",
					RefreshToken:         "ghr_rotated_2",
					AccessTokenExpiresIn: 8 * time.Hour,
				}, nil
			default:
				return provider.TokenResponse{}, errors.New("bad_refresh_token")
			}
		})
	tokenResp, firstJWT := runBuiltinFullFlow(t, h, "alice")
	refreshToken, _ := tokenResp["refresh_token"].(string)
	if refreshToken == "" {
		t.Fatal("initial token response missing refresh_token")
	}

	firstResult, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("first delegated rotation: %v", err)
	}
	if firstResult.AccessToken != "gho_rotated_1" {
		t.Fatalf("first delegated rotation access token: got %q, want %q", firstResult.AccessToken, "gho_rotated_1")
	}

	refreshResp := runBuiltinGatewayRefresh(t, h, refreshToken)
	secondJWT, _ := refreshResp["access_token"].(string)
	secondRefreshToken, _ := refreshResp["refresh_token"].(string)
	if secondJWT == "" || secondRefreshToken == "" {
		t.Fatalf("gateway refresh response missing tokens: access=%t refresh=%t", secondJWT != "", secondRefreshToken != "")
	}
	secondRecord, ok := h.store.LookupToken(secondJWT)
	if !ok {
		t.Fatal("gateway refresh grant did not cache the new JWT")
	}
	if secondRecord.ProviderAccessToken != "gho_rotated_1" || secondRecord.ProviderRefreshToken != "ghr_rotated_1" {
		t.Fatalf("gateway refresh restored stale provider generation: access=%q refresh=%q",
			secondRecord.ProviderAccessToken, secondRecord.ProviderRefreshToken)
	}
	if got := h.store.LookupRefreshTokenProviderAccessToken(secondRefreshToken); got != "gho_rotated_1" {
		t.Fatalf("new refresh-token entry provider access token: got %q, want %q", got, "gho_rotated_1")
	}
	if got, _ := h.store.LookupRefreshTokenProviderRefresh(secondRefreshToken); got != "ghr_rotated_1" {
		t.Fatalf("new refresh-token entry provider refresh token: got %q, want %q", got, "ghr_rotated_1")
	}

	// 同一 subject の旧 JWT と新 JWT は同じ provider expiry を持つため、
	// 新 JWT の復元値を検証する前にクライアントが更新済みとみなして旧 JWT を除外する。
	h.InvalidateCachedToken(firstJWT)
	secondResult, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("delegated access after gateway refresh: %v", err)
	}
	if secondResult.AccessToken != "gho_rotated_2" {
		t.Fatalf("delegated access after gateway refresh: got %q, want %q", secondResult.AccessToken, "gho_rotated_2")
	}
	if len(observedRefreshTokens) != 2 || observedRefreshTokens[0] != "ghr_original" || observedRefreshTokens[1] != "ghr_rotated_1" {
		t.Fatalf("provider refresh sequence: got %v, want [ghr_original ghr_rotated_1]", observedRefreshTokens)
	}
}

func TestEnsureFreshAccessTokenForSubject_BuiltinRotationSerializesGatewayRefresh(t *testing.T) {
	rotationStarted := make(chan struct{})
	releaseRotation := make(chan struct{})
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_original", "ghr_original", 30*time.Second,
		func(_ context.Context, rt string) (provider.TokenResponse, error) {
			if rt != "ghr_original" {
				return provider.TokenResponse{}, fmt.Errorf("unexpected refresh token %q", rt)
			}
			close(rotationStarted)
			<-releaseRotation
			return provider.TokenResponse{
				AccessToken:          "gho_rotated",
				RefreshToken:         "ghr_rotated",
				AccessTokenExpiresIn: 8 * time.Hour,
			}, nil
		})
	tokenResp, _ := runBuiltinFullFlow(t, h, "alice")
	refreshToken, _ := tokenResp["refresh_token"].(string)

	rotationResult := make(chan error, 1)
	go func() {
		_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
		rotationResult <- err
	}()
	<-rotationStarted

	refreshStarted := make(chan struct{})
	refreshDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		close(refreshStarted)
		body := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
		req := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.Token(rec, req)
		refreshDone <- rec
	}()
	<-refreshStarted

	select {
	case rec := <-refreshDone:
		t.Fatalf("gateway refresh completed before provider rotation: status=%d body=%s", rec.Code, rec.Body.String())
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseRotation)
	if err := <-rotationResult; err != nil {
		t.Fatalf("delegated rotation: %v", err)
	}
	rec := <-refreshDone
	if rec.Code != http.StatusOK {
		t.Fatalf("gateway refresh: got %d; body=%s", rec.Code, rec.Body.String())
	}
	var response map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatalf("decode gateway refresh response: %v", err)
	}
	newJWT, _ := response["access_token"].(string)
	newRefreshToken, _ := response["refresh_token"].(string)
	newRecord, ok := h.store.LookupToken(newJWT)
	if !ok {
		t.Fatal("gateway refresh did not cache the new JWT")
	}
	if newRecord.ProviderAccessToken != "gho_rotated" || newRecord.ProviderRefreshToken != "ghr_rotated" {
		t.Fatalf("gateway refresh copied stale provider generation: access=%q refresh=%q",
			newRecord.ProviderAccessToken, newRecord.ProviderRefreshToken)
	}
	if got, _ := h.store.LookupRefreshTokenProviderRefresh(newRefreshToken); got != "ghr_rotated" {
		t.Fatalf("new refresh-token entry provider refresh token: got %q, want %q", got, "ghr_rotated")
	}
}

func TestEnsureFreshAccessTokenForSubject_BuiltinRotationAfterGatewayRefreshUpdatesCurrentFamily(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_original", "ghr_original", 30*time.Second,
		func(_ context.Context, rt string) (provider.TokenResponse, error) {
			if rt != "ghr_original" {
				return provider.TokenResponse{}, fmt.Errorf("unexpected refresh token %q", rt)
			}
			return provider.TokenResponse{
				AccessToken:          "gho_rotated",
				RefreshToken:         "ghr_rotated",
				AccessTokenExpiresIn: 8 * time.Hour,
			}, nil
		})
	tokenResp, firstJWT := runBuiltinFullFlow(t, h, "alice")
	firstRefreshToken, _ := tokenResp["refresh_token"].(string)

	response := runBuiltinGatewayRefresh(t, h, firstRefreshToken)
	currentJWT, _ := response["access_token"].(string)
	currentRefreshToken, _ := response["refresh_token"].(string)

	if result := h.runBuiltinRotation(context.Background(), firstJWT); !result.ok {
		t.Fatalf("provider rotation after gateway refresh did not succeed: %+v", result)
	}
	currentRecord, ok := h.store.LookupToken(currentJWT)
	if !ok {
		t.Fatal("current gateway JWT is not cached")
	}
	if currentRecord.ProviderAccessToken != "gho_rotated" || currentRecord.ProviderRefreshToken != "ghr_rotated" {
		t.Fatalf("current gateway JWT kept stale provider metadata: access=%q refresh=%q",
			currentRecord.ProviderAccessToken, currentRecord.ProviderRefreshToken)
	}
	if got, _ := h.store.LookupRefreshTokenProviderRefresh(currentRefreshToken); got != "ghr_rotated" {
		t.Fatalf("current refresh-token entry provider refresh token: got %q, want %q", got, "ghr_rotated")
	}
}

func TestEnsureFreshAccessTokenForSubject_BuiltinPermanentFailureAfterGatewayRefreshRevokesCurrentFamily(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_poisoned", "ghr_poisoned", 30*time.Second,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, errors.New("bad_refresh_token")
		})
	tokenResp, firstJWT := runBuiltinFullFlow(t, h, "alice")
	firstRefreshToken, _ := tokenResp["refresh_token"].(string)

	response := runBuiltinGatewayRefresh(t, h, firstRefreshToken)
	currentJWT, _ := response["access_token"].(string)
	currentRefreshToken, _ := response["refresh_token"].(string)

	if result := h.runBuiltinRotation(context.Background(), firstJWT); result.ok {
		t.Fatalf("permanently rejected rotation unexpectedly succeeded: %+v", result)
	}
	if !h.store.IsRotationPermanentlyFailed(currentJWT) {
		t.Fatal("current gateway JWT was not marked permanently failed")
	}
	if _, _, _, _, revoked, ok := h.store.LookupAnyRefreshToken(currentRefreshToken); !ok || !revoked {
		t.Fatalf("current refresh-token family must be revoked: ok=%t revoked=%t", ok, revoked)
	}
	if _, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice"); !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("delegated access after family failure: got %v, want ErrSubjectNotFound", err)
	}
}

// TestEnsureFreshAccessTokenForSubject_BuiltinRotationTransientFailure
// verifies that a transient provider error (5xx/network) surfaces
// ErrRotationFailed without marking the token permanently dead — the
// metadata must remain intact so the next call can retry.
func TestEnsureFreshAccessTokenForSubject_BuiltinRotationTransientFailure(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_dying", "ghr_dying", 30*time.Second,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, &provider.UpstreamError{Err: errors.New("502 from github")}
		})
	_, jwt := runBuiltinFullFlow(t, h, "alice")

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("err: got %v, want ErrRotationFailed", err)
	}
	rec, ok := h.store.LookupToken(jwt)
	if !ok {
		t.Fatal("expected JWT record to still exist after transient failure")
	}
	if rec.ProviderRefreshToken != "ghr_dying" {
		t.Errorf("transient failure must not clear refresh metadata, got %q", rec.ProviderRefreshToken)
	}
}

// TestEnsureFreshAccessTokenForSubject_BuiltinRotationPermanentlyFailed
// verifies that a permanent provider rejection (bad_refresh_token) clears the
// rotation metadata and evicts the subject index entry via
// MarkRotationPermanentlyFailed, so a subsequent call returns
// ErrSubjectNotFound instead of repeatedly retrying a dead refresh token or
// handing out the now-unusable cached bearer.
func TestEnsureFreshAccessTokenForSubject_BuiltinRotationPermanentlyFailed(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_poisoned", "ghr_poisoned", 30*time.Second,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{}, errors.New("bad_refresh_token")
		})
	tokenResp, jwt := runBuiltinFullFlow(t, h, "alice")
	refreshToken, _ := tokenResp["refresh_token"].(string)

	_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrRotationFailed) {
		t.Fatalf("first call err: got %v, want ErrRotationFailed", err)
	}
	rec, ok := h.store.LookupToken(jwt)
	if !ok {
		t.Fatal("token entry should still exist (only metadata is cleared)")
	}
	if rec.ProviderRefreshToken != "" || !rec.ProviderAccessExpiry.IsZero() {
		t.Errorf("expected provider refresh metadata cleared, got refresh=%q expiry=%v",
			rec.ProviderRefreshToken, rec.ProviderAccessExpiry)
	}

	// Second call: the subject index entry was evicted, so the dead bearer is
	// never returned again.
	_, err = h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if !errors.Is(err, ErrSubjectNotFound) {
		t.Fatalf("second call err: got %v, want ErrSubjectNotFound", err)
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusBadRequest {
		t.Fatalf("gateway refresh after permanent failure: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	if _, _, _, _, revoked, ok := h.store.LookupAnyRefreshToken(refreshToken); !ok || !revoked {
		t.Fatalf("provider failure must revoke the active refresh-token family: ok=%t revoked=%t", ok, revoked)
	}
}

// TestEnsureFreshAccessTokenForSubject_BuiltinCachedOutsideLeeway verifies
// that a JWT whose provider expiry is well past the leeway window returns
// the cached provider token as-is without invoking rotation.
func TestEnsureFreshAccessTokenForSubject_BuiltinCachedOutsideLeeway(t *testing.T) {
	h := newDelegatedBuiltinRotationTestHandler(t, "gho_fresh", "ghr_fresh", 1*time.Hour,
		func(_ context.Context, _ string) (provider.TokenResponse, error) {
			t.Fatal("RefreshToken should not be called when expiry is outside leeway")
			return provider.TokenResponse{}, nil
		})
	_, jwt := runBuiltinFullFlow(t, h, "alice")

	res, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
	if err != nil {
		t.Fatalf("EnsureFreshAccessTokenForSubject: %v", err)
	}
	if res.AccessToken != "gho_fresh" {
		t.Errorf("access token: got %q, want %q", res.AccessToken, "gho_fresh")
	}
	if _, ok := h.store.LookupToken(jwt); !ok {
		t.Fatal("expected JWT record to still exist")
	}
}
