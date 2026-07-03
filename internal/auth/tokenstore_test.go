package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── helpers ──────────────────────────────────────────────────────────────────

func testTokenStoreContract(t *testing.T, ts TokenStore) {
	t.Helper()

	// Save and Lookup — hit
	if err := ts.Save("tok1", "alice", []string{"https://gw.example/mcp"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	rec, ok := ts.Lookup("tok1")
	if !ok {
		t.Fatal("Lookup: expected hit after Save")
	}
	if rec.Subject != "alice" {
		t.Errorf("Lookup: subject got %q, want %q", rec.Subject, "alice")
	}
	if !rec.HasAudience("https://gw.example/mcp") {
		t.Errorf("Lookup: audiences got %#v, want https://gw.example/mcp", rec.Audiences)
	}

	// Lookup — miss for unknown token
	if _, ok := ts.Lookup("unknown"); ok {
		t.Error("Lookup: expected miss for unknown token")
	}

	// Delete
	if err := ts.Delete("tok1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := ts.Lookup("tok1"); ok {
		t.Error("Lookup: expected miss after Delete")
	}

	// Expired entries are not returned by Lookup
	if err := ts.Save("tok2", "bob", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if _, ok := ts.Lookup("tok2"); ok {
		t.Error("Lookup: expected miss for expired entry")
	}

	// MarkRotationFailed — sets RotationPermanentlyFailed flag; Lookup returns it
	if err := ts.Save("tok-pf", "carol", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save tok-pf: %v", err)
	}
	if err := ts.MarkRotationFailed("tok-pf"); err != nil {
		t.Fatalf("MarkRotationFailed: %v", err)
	}
	rec3, ok3 := ts.Lookup("tok-pf")
	if !ok3 {
		t.Fatal("MarkRotationFailed: token should still be present (not evicted)")
	}
	if !rec3.RotationPermanentlyFailed {
		t.Error("MarkRotationFailed: RotationPermanentlyFailed should be true after marking")
	}

	// MarkRotationFailed on absent token is a no-op (no error)
	if err := ts.MarkRotationFailed("no-such-token"); err != nil {
		t.Fatalf("MarkRotationFailed on absent token returned error: %v", err)
	}

	// Sweep removes expired entries
	if err := ts.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// SaveNonce attaches nonce to an existing entry; Lookup returns it.
	if err := ts.Save("tok-nonce", "dave", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save tok-nonce: %v", err)
	}
	if err := ts.SaveNonce("tok-nonce", "nonce-abc"); err != nil {
		t.Fatalf("SaveNonce: %v", err)
	}
	recN, okN := ts.Lookup("tok-nonce")
	if !okN {
		t.Fatal("Lookup tok-nonce: expected hit after SaveNonce")
	}
	if recN.Nonce != "nonce-abc" {
		t.Errorf("SaveNonce: Nonce got %q, want %q", recN.Nonce, "nonce-abc")
	}

	// SaveNonce on absent token is a no-op (no error).
	if err := ts.SaveNonce("no-such-token", "nonce-xyz"); err != nil {
		t.Fatalf("SaveNonce on absent token returned error: %v", err)
	}

	// SaveNonce on expired token is a no-op (no error).
	if err := ts.Save("tok-expired-nonce", "eve", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired nonce token: %v", err)
	}
	if err := ts.SaveNonce("tok-expired-nonce", "nonce-xyz"); err != nil {
		t.Fatalf("SaveNonce on expired token returned error: %v", err)
	}

	// SaveProviderAccessToken attaches the provider token to an existing entry;
	// Lookup returns it.
	if err := ts.Save("tok-pat", "frank", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save tok-pat: %v", err)
	}
	if err := ts.SaveProviderAccessToken("tok-pat", "gho_abc123"); err != nil {
		t.Fatalf("SaveProviderAccessToken: %v", err)
	}
	recPAT, okPAT := ts.Lookup("tok-pat")
	if !okPAT {
		t.Fatal("Lookup tok-pat: expected hit after SaveProviderAccessToken")
	}
	if recPAT.ProviderAccessToken != "gho_abc123" {
		t.Errorf("SaveProviderAccessToken: ProviderAccessToken got %q, want %q", recPAT.ProviderAccessToken, "gho_abc123")
	}

	// SaveProviderAccessToken on absent token is a no-op (no error, no entry created).
	if err := ts.SaveProviderAccessToken("no-such-token", "gho_ghost"); err != nil {
		t.Fatalf("SaveProviderAccessToken on absent token returned error: %v", err)
	}
	if _, ok := ts.Lookup("no-such-token"); ok {
		t.Error("SaveProviderAccessToken must not create an entry for an unknown token")
	}

	// SaveJti attaches the JWT ID to an existing entry; Lookup returns it.
	if err := ts.Save("tok-jti", "grace", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save tok-jti: %v", err)
	}
	if err := ts.SaveJti("tok-jti", "jti-abc123"); err != nil {
		t.Fatalf("SaveJti: %v", err)
	}
	recJti, okJti := ts.Lookup("tok-jti")
	if !okJti {
		t.Fatal("Lookup tok-jti: expected hit after SaveJti")
	}
	if recJti.Jti != "jti-abc123" {
		t.Errorf("SaveJti: Jti got %q, want %q", recJti.Jti, "jti-abc123")
	}

	// SaveJti on absent token is a no-op (no error, no entry created).
	if err := ts.SaveJti("no-such-token", "jti-ghost"); err != nil {
		t.Fatalf("SaveJti on absent token returned error: %v", err)
	}
	if _, ok := ts.Lookup("no-such-token"); ok {
		t.Error("SaveJti must not create an entry for an unknown token")
	}

	// SaveJti on expired token is a no-op (no error).
	if err := ts.Save("tok-expired-jti", "heidi", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired jti token: %v", err)
	}
	if err := ts.SaveJti("tok-expired-jti", "jti-xyz"); err != nil {
		t.Fatalf("SaveJti on expired token returned error: %v", err)
	}
}

// ── memTokenStore ─────────────────────────────────────────────────────────────

func TestMemTokenStore(t *testing.T) {
	testTokenStoreContract(t, NewMemTokenStore())
}

func TestMemTokenStoreMultiple(t *testing.T) {
	ts := NewMemTokenStore()

	for i, name := range []string{"alice", "bob", "carol"} {
		token := string(rune('a' + i))
		if err := ts.Save(token, name, nil, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Save %q: %v", token, err)
		}
	}

	for i, want := range []string{"alice", "bob", "carol"} {
		token := string(rune('a' + i))
		got, ok := ts.Lookup(token)
		if !ok {
			t.Fatalf("Lookup %q: expected hit", token)
		}
		if got.Subject != want {
			t.Errorf("Lookup %q: got %q, want %q", token, got.Subject, want)
		}
	}
}

// ── fileTokenStore ────────────────────────────────────────────────────────────

func tempStorePath(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	return filepath.Join(dir, "tokens.json")
}

func TestFileTokenStore(t *testing.T) {
	ts, err := NewFileTokenStore(tempStorePath(t))
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	testTokenStoreContract(t, ts)
}

// TestFileTokenStorePersistence verifies that entries survive a reload
// (simulating a container restart).
func TestFileTokenStorePersistence(t *testing.T) {
	path := tempStorePath(t)

	ts1, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileTokenStore: %v", err)
	}
	if err := ts1.Save("persist-tok", "dave", []string{"https://gw.example/mcp"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from same path — simulates container restart.
	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	rec, ok := ts2.Lookup("persist-tok")
	if !ok {
		t.Fatal("after reload: expected cache hit for previously saved token")
	}
	if rec.Subject != "dave" {
		t.Errorf("after reload: subject got %q, want %q", rec.Subject, "dave")
	}
	if !rec.HasAudience("https://gw.example/mcp") {
		t.Errorf("after reload: audiences got %#v", rec.Audiences)
	}
}

// TestFileTokenStoreMarkRotationFailedPersists verifies that the
// RotationPermanentlyFailed flag set via MarkRotationFailed survives a gateway
// restart (reload from the file-backed store).  This is the durability
// property that prevents a dead bearer from being re-inserted into the subject
// index after a restart.
func TestFileTokenStoreMarkRotationFailedPersists(t *testing.T) {
	path := tempStorePath(t)

	ts1, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	if err := ts1.Save("pf-tok", "alice", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ts1.MarkRotationFailed("pf-tok"); err != nil {
		t.Fatalf("MarkRotationFailed: %v", err)
	}

	// Reload from same path — simulates gateway restart.
	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	rec, ok := ts2.Lookup("pf-tok")
	if !ok {
		t.Fatal("after reload: token should still be present (not evicted)")
	}
	if rec.Subject != "alice" {
		t.Errorf("after reload: subject got %q, want %q", rec.Subject, "alice")
	}
	if !rec.RotationPermanentlyFailed {
		t.Error("after reload: RotationPermanentlyFailed should be true")
	}
}

// TestFileTokenStoreMarkRotationFailedFlushFailureRollsBack verifies that
// MarkRotationFailed rolls back the in-memory mutation when the flush fails.
func TestFileTokenStoreMarkRotationFailedFlushFailureRollsBack(t *testing.T) {
	path := tempStorePath(t)
	ts, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	if err := ts.Save("pf-rb", "bob", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	parent := filepath.Dir(path)
	t.Cleanup(func() { _ = os.MkdirAll(parent, 0o700) })
	if err := os.RemoveAll(parent); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	err = ts.MarkRotationFailed("pf-rb")
	if err == nil {
		t.Fatal("expected MarkRotationFailed to surface flush failure")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatalf("recreate parent: %v", err)
	}
	rec, ok := ts.Lookup("pf-rb")
	if !ok {
		t.Fatal("Lookup after rollback: expected entry to still be present")
	}
	if rec.RotationPermanentlyFailed {
		t.Error("rollback: RotationPermanentlyFailed should remain false after flush failure")
	}
}

// TestFileTokenStoreProviderRefreshRoundTrip verifies that provider refresh
// metadata persisted via SaveProviderRefresh survives a reload of the
// FileTokenStore.  Restart preservation is the contract relied on by the
// rotation path so that an in-flight refresh-token / access-expiry pair is
// not lost on container reboot.
func TestFileTokenStoreProviderRefreshRoundTrip(t *testing.T) {
	cases := []struct {
		name             string
		setup            func(t *testing.T, ts TokenStore)
		expectedRefresh  string
		expectedAccessIn time.Duration
		expectExpiryZero bool
	}{
		{
			name: "metadata attached after Save survives reload",
			setup: func(t *testing.T, ts TokenStore) {
				t.Helper()
				if err := ts.Save("rt-host", "alice", []string{"https://gw.example/mcp"}, time.Now().Add(time.Hour)); err != nil {
					t.Fatalf("Save: %v", err)
				}
				if err := ts.SaveProviderRefresh("rt-host", "ghrt-1", time.Now().Add(30*time.Minute)); err != nil {
					t.Fatalf("SaveProviderRefresh: %v", err)
				}
			},
			expectedRefresh:  "ghrt-1",
			expectedAccessIn: 30 * time.Minute,
		},
		{
			name: "SaveProviderRefresh on missing entry is a no-op (not resurrected on reload)",
			setup: func(t *testing.T, ts TokenStore) {
				t.Helper()
				if err := ts.SaveProviderRefresh("ghost", "ghrt-missing", time.Now().Add(30*time.Minute)); err != nil {
					t.Fatalf("SaveProviderRefresh: %v", err)
				}
			},
			expectExpiryZero: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := tempStorePath(t)
			ts1, err := NewFileTokenStore(path)
			if err != nil {
				t.Fatalf("initial NewFileTokenStore: %v", err)
			}
			tc.setup(t, ts1)

			ts2, err := NewFileTokenStore(path)
			if err != nil {
				t.Fatalf("reloaded NewFileTokenStore: %v", err)
			}
			if tc.expectedRefresh == "" {
				if _, ok := ts2.Lookup("ghost"); ok {
					t.Fatal("SaveProviderRefresh must not create an entry for an unknown token")
				}
				return
			}
			rec, ok := ts2.Lookup("rt-host")
			if !ok {
				t.Fatal("after reload: expected cache hit for rt-host")
			}
			if rec.ProviderRefreshToken != tc.expectedRefresh {
				t.Errorf("provider refresh: got %q, want %q", rec.ProviderRefreshToken, tc.expectedRefresh)
			}
			if rec.ProviderAccessExpiry.IsZero() {
				t.Fatal("provider access expiry: got zero, want non-zero after reload")
			}
			// Use a wide tolerance because file IO timing varies; what matters
			// is that the expiry remains close to the original (not zeroed).
			diff := time.Until(rec.ProviderAccessExpiry)
			if diff < tc.expectedAccessIn-time.Minute || diff > tc.expectedAccessIn+time.Minute {
				t.Errorf("provider access expiry drift: got %v, want ~%v", diff, tc.expectedAccessIn)
			}
		})
	}
}

// TestFileTokenStoreSaveProviderRefreshFlushFailureRollsBack verifies that a
// flush failure during SaveProviderRefresh rolls back the in-memory change so
// the cache and disk remain consistent. We trigger flush failure by replacing
// the store directory with a non-writable read-only file once setup is done.
func TestFileTokenStoreSaveProviderRefreshFlushFailureRollsBack(t *testing.T) {
	path := tempStorePath(t)
	ts, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	if err := ts.Save("rt-host", "alice", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ts.SaveProviderRefresh("rt-host", "ghrt-1", time.Now().Add(30*time.Minute)); err != nil {
		t.Fatalf("first SaveProviderRefresh: %v", err)
	}

	// Force flush failure by removing the parent directory so rename targets fail.
	parent := filepath.Dir(path)
	t.Cleanup(func() { _ = os.MkdirAll(parent, 0o700) })
	if err := os.RemoveAll(parent); err != nil {
		t.Fatalf("RemoveAll: %v", err)
	}

	err = ts.SaveProviderRefresh("rt-host", "ghrt-2", time.Now().Add(45*time.Minute))
	if err == nil {
		t.Fatal("expected SaveProviderRefresh to surface flush failure")
	}
	// Restore the directory before asserting Lookup so the assertion is
	// independent of FS state.
	if err := os.MkdirAll(parent, 0o700); err != nil {
		t.Fatalf("recreate parent: %v", err)
	}
	rec, ok := ts.Lookup("rt-host")
	if !ok {
		t.Fatal("Lookup after rollback: expected entry to still be present")
	}
	if rec.ProviderRefreshToken != "ghrt-1" {
		t.Errorf("rollback: provider refresh got %q, want previous %q", rec.ProviderRefreshToken, "ghrt-1")
	}
}

// TestFileTokenStoreProviderAccessTokenRoundTrip verifies that the provider
// access token persisted via SaveProviderAccessToken survives a reload of the
// FileTokenStore. This is the on-disk contract EnsureFreshAccessTokenForSubject
// relies on to recover a builtin-mode GitHub token after a gateway restart.
func TestFileTokenStoreProviderAccessTokenRoundTrip(t *testing.T) {
	path := tempStorePath(t)
	ts1, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileTokenStore: %v", err)
	}
	if err := ts1.Save("jwt-host", "alice", []string{"https://gw.example/mcp"}, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ts1.SaveProviderAccessToken("jwt-host", "gho_alice1"); err != nil {
		t.Fatalf("SaveProviderAccessToken: %v", err)
	}

	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	rec, ok := ts2.Lookup("jwt-host")
	if !ok {
		t.Fatal("after reload: expected cache hit for jwt-host")
	}
	if rec.ProviderAccessToken != "gho_alice1" {
		t.Errorf("provider access token after reload: got %q, want %q", rec.ProviderAccessToken, "gho_alice1")
	}
}

// TestFileTokenStoreExpiredNotLoaded verifies that expired entries written before
// a reload do not surface after the reload's startup sweep.
func TestFileTokenStoreExpiredNotLoaded(t *testing.T) {
	path := tempStorePath(t)

	ts1, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileTokenStore: %v", err)
	}
	// Save an entry that is already expired.
	if err := ts1.Save("expired-tok", "eve", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload: the startup sweep should discard the expired entry.
	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	if _, ok := ts2.Lookup("expired-tok"); ok {
		t.Error("after reload: expired entry should not be returned")
	}
}

// TestFileTokenStoreFilePermissions verifies that the store file is written
// with mode 0600 on Unix systems. Skipped on Windows where ACLs govern access.
func TestFileTokenStoreFilePermissions(t *testing.T) {
	if isWindows() {
		t.Skip("file permission bits not enforced on Windows")
	}
	path := tempStorePath(t)
	ts, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	if err := ts.Save("tok", "frank", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions: got %04o, want 0600", perm)
	}
}

// TestFileTokenStoreMissingFileOK verifies that a non-existent store file is
// treated as an empty store (no error on startup).
func TestFileTokenStoreMissingFileOK(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent.json")
	if _, err := NewFileTokenStore(path); err != nil {
		t.Fatalf("NewFileTokenStore with missing file: %v", err)
	}
}

// TestFileTokenStoreParentIsFile verifies that NewFileTokenStore returns an
// error when the parent path is a regular file rather than a directory.
func TestFileTokenStoreParentIsFile(t *testing.T) {
	// Create a regular file and use it as the "directory" component.
	dir := t.TempDir()
	notADir := filepath.Join(dir, "file.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0600); err != nil {
		t.Fatalf("setup: WriteFile: %v", err)
	}
	path := filepath.Join(notADir, "tokens.json")
	if _, err := NewFileTokenStore(path); err == nil {
		t.Fatal("expected error when parent path is a file, got nil")
	}
}

// TestFileTokenStoreParentNotWritable verifies that NewFileTokenStore returns
// an error when the parent directory exists but is not writable.
// Skipped on Windows where removing write bits via chmod is not reliable.
func TestFileTokenStoreParentNotWritable(t *testing.T) {
	if isWindows() {
		t.Skip("Unix-only: chmod write-bit removal not reliable on Windows")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0700) }) // allow cleanup
	path := filepath.Join(roDir, "tokens.json")
	if _, err := NewFileTokenStore(path); err == nil {
		t.Fatal("expected error for unwritable parent directory, got nil")
	}
}

// TestFileTokenStoreSweepWritesToDisk verifies that Sweep flushes the pruned
// state to disk.
func TestFileTokenStoreSweepWritesToDisk(t *testing.T) {
	path := tempStorePath(t)

	ts1, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileTokenStore: %v", err)
	}
	// One valid, one expired.
	if err := ts1.Save("valid-tok", "grace", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save valid token: %v", err)
	}
	if err := ts1.Save("stale-tok", "harry", nil, time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save stale token: %v", err)
	}
	if err := ts1.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// Reload: only valid-tok should be present.
	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	if _, ok := ts2.Lookup("valid-tok"); !ok {
		t.Error("after sweep+reload: valid token should still be present")
	}
	if _, ok := ts2.Lookup("stale-tok"); ok {
		t.Error("after sweep+reload: stale token should have been removed")
	}
}

// ── RefreshTokenStore helpers and tests ───────────────────────────────────────

func testRefreshTokenStoreContract(t *testing.T, rts RefreshTokenStore) {
	t.Helper()

	// Save and Lookup — hit
	exp := time.Now().Add(time.Hour)
	if err := rts.Save("rt1", "access-tok-1", "https://gw.example/mcp", "fid-abc", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, gotAudience, gotFamilyID, gotExp, ok := rts.Lookup("rt1")
	if !ok {
		t.Fatal("Lookup: expected hit after Save")
	}
	if got != "access-tok-1" {
		t.Errorf("Lookup: accessToken got %q, want %q", got, "access-tok-1")
	}
	if gotAudience != "https://gw.example/mcp" {
		t.Errorf("Lookup: audience got %q, want %q", gotAudience, "https://gw.example/mcp")
	}
	if gotFamilyID != "fid-abc" {
		t.Errorf("Lookup: familyID got %q, want %q", gotFamilyID, "fid-abc")
	}
	if gotExp.IsZero() {
		t.Error("Lookup: expiresAt should not be zero")
	}

	// Lookup — miss for unknown token
	if _, _, _, _, ok := rts.Lookup("unknown"); ok {
		t.Error("Lookup: expected miss for unknown token")
	}

	// Delete
	if err := rts.Delete("rt1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, _, _, ok := rts.Lookup("rt1"); ok {
		t.Error("Lookup: expected miss after Delete")
	}

	// Expired entries are not returned by Lookup
	if err := rts.Save("rt2", "access-tok-2", "", "fid-xyz", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if _, _, _, _, ok := rts.Lookup("rt2"); ok {
		t.Error("Lookup: expected miss for expired entry")
	}

	// Sweep removes expired entries
	if err := rts.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// SaveNonce attaches nonce to an existing RT entry; LookupNonce returns it.
	if err := rts.Save("rt-nonce", "access-tok-n", "", "fid-n", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-nonce: %v", err)
	}
	if err := rts.SaveNonce("rt-nonce", "nonce-abc"); err != nil {
		t.Fatalf("SaveNonce: %v", err)
	}
	if got := rts.LookupNonce("rt-nonce"); got != "nonce-abc" {
		t.Errorf("LookupNonce: got %q, want %q", got, "nonce-abc")
	}
	// LookupNonce returns "" for unknown token.
	if got := rts.LookupNonce("no-such-rt"); got != "" {
		t.Errorf("LookupNonce on absent: got %q, want empty", got)
	}
	// SaveNonce on absent token is a no-op (no error).
	if err := rts.SaveNonce("no-such-rt", "nonce-xyz"); err != nil {
		t.Fatalf("SaveNonce on absent returned error: %v", err)
	}
	// LookupNonce returns "" for expired token.
	if err := rts.Save("rt-nonce-exp", "access-tok-exp", "", "fid-exp", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired rt-nonce: %v", err)
	}
	if got := rts.LookupNonce("rt-nonce-exp"); got != "" {
		t.Errorf("LookupNonce on expired: got %q, want empty", got)
	}

	// SaveProviderAccessToken attaches a provider token to an existing RT
	// entry; LookupProviderAccessToken returns it.
	if err := rts.Save("rt-pat", "access-tok-pat", "", "fid-pat", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-pat: %v", err)
	}
	if err := rts.SaveProviderAccessToken("rt-pat", "gho_pat1"); err != nil {
		t.Fatalf("SaveProviderAccessToken: %v", err)
	}
	if got := rts.LookupProviderAccessToken("rt-pat"); got != "gho_pat1" {
		t.Errorf("LookupProviderAccessToken: got %q, want %q", got, "gho_pat1")
	}
	// LookupProviderAccessToken returns "" for unknown token.
	if got := rts.LookupProviderAccessToken("no-such-rt"); got != "" {
		t.Errorf("LookupProviderAccessToken on absent: got %q, want empty", got)
	}
	// SaveProviderAccessToken on absent token is a no-op (no error).
	if err := rts.SaveProviderAccessToken("no-such-rt", "gho_ghost"); err != nil {
		t.Fatalf("SaveProviderAccessToken on absent returned error: %v", err)
	}
	// LookupProviderAccessToken remains readable after soft-revocation (Revoke),
	// mirroring LookupNonce: tokenRefresh reads it via ReserveRefreshToken,
	// which soft-revokes rather than deletes.
	if err := rts.Save("rt-pat-revoked", "access-tok-rev", "", "fid-rev", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-pat-revoked: %v", err)
	}
	if err := rts.SaveProviderAccessToken("rt-pat-revoked", "gho_rev1"); err != nil {
		t.Fatalf("SaveProviderAccessToken rt-pat-revoked: %v", err)
	}
	if err := rts.Revoke("rt-pat-revoked"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got := rts.LookupProviderAccessToken("rt-pat-revoked"); got != "gho_rev1" {
		t.Errorf("LookupProviderAccessToken after Revoke: got %q, want %q (soft-revoked entries must remain readable)", got, "gho_rev1")
	}

	// SaveProviderRefresh attaches provider refresh metadata (builtin-mode
	// rotation, #190) to an existing RT entry; LookupProviderRefresh returns it.
	prExpiry := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	if err := rts.Save("rt-prt", "access-tok-prt", "", "fid-prt", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-prt: %v", err)
	}
	if err := rts.SaveProviderRefresh("rt-prt", "ghr_prt1", prExpiry); err != nil {
		t.Fatalf("SaveProviderRefresh: %v", err)
	}
	gotPRT, gotPRExpiry := rts.LookupProviderRefresh("rt-prt")
	if gotPRT != "ghr_prt1" {
		t.Errorf("LookupProviderRefresh: providerRefreshToken got %q, want %q", gotPRT, "ghr_prt1")
	}
	if !gotPRExpiry.Equal(prExpiry) {
		t.Errorf("LookupProviderRefresh: providerAccessExpiry got %v, want %v", gotPRExpiry, prExpiry)
	}
	// LookupProviderRefresh returns ("", zero) for unknown token.
	if got, gotExp := rts.LookupProviderRefresh("no-such-rt"); got != "" || !gotExp.IsZero() {
		t.Errorf("LookupProviderRefresh on absent: got (%q, %v), want (\"\", zero)", got, gotExp)
	}
	// SaveProviderRefresh on absent token is a no-op (no error).
	if err := rts.SaveProviderRefresh("no-such-rt", "ghr_ghost", prExpiry); err != nil {
		t.Fatalf("SaveProviderRefresh on absent returned error: %v", err)
	}
	// LookupProviderRefresh remains readable after soft-revocation (Revoke),
	// mirroring LookupProviderAccessToken: tokenRefresh reads it via
	// ReserveRefreshToken, which soft-revokes rather than deletes.
	if err := rts.Save("rt-prt-revoked", "access-tok-prt-rev", "", "fid-prt-rev", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-prt-revoked: %v", err)
	}
	if err := rts.SaveProviderRefresh("rt-prt-revoked", "ghr_rev1", prExpiry); err != nil {
		t.Fatalf("SaveProviderRefresh rt-prt-revoked: %v", err)
	}
	if err := rts.Revoke("rt-prt-revoked"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if got, _ := rts.LookupProviderRefresh("rt-prt-revoked"); got != "ghr_rev1" {
		t.Errorf("LookupProviderRefresh after Revoke: got %q, want %q (soft-revoked entries must remain readable)", got, "ghr_rev1")
	}

	// IsJTIRevoked is false before RevokeJTI.
	if rts.IsJTIRevoked("jti-1") {
		t.Error("IsJTIRevoked: expected false before RevokeJTI")
	}
	// RevokeJTI adds an entry that IsJTIRevoked then reports as revoked.
	if err := rts.RevokeJTI("jti-1", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("RevokeJTI: %v", err)
	}
	if !rts.IsJTIRevoked("jti-1") {
		t.Error("IsJTIRevoked: expected true after RevokeJTI")
	}
	// A jti revoked with an already-past expiresAt is not reported as revoked
	// (mirrors natural expiry — the entry is inert even before Sweep runs).
	if err := rts.RevokeJTI("jti-expired", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("RevokeJTI (expired): %v", err)
	}
	if rts.IsJTIRevoked("jti-expired") {
		t.Error("IsJTIRevoked: expected false for a jti revoked with a past expiresAt")
	}
	// Sweep must not error with revoked jti entries present (some already expired).
	if err := rts.Sweep(); err != nil {
		t.Fatalf("Sweep with revoked jti entries: %v", err)
	}
	// The still-valid jti survives Sweep.
	if !rts.IsJTIRevoked("jti-1") {
		t.Error("IsJTIRevoked: jti-1 should survive Sweep (not yet expired)")
	}

	// RevokeFamily returns the family's current access token pointer — the
	// value most recently written by Save for that family — even though the
	// row backing it was never itself revoked before this call. Unlike a
	// row-scan for "non-revoked", the pointer is unaffected by an older
	// sibling's revoked flag: it always reflects the latest Save.
	if err := rts.Save("rt-fam-old", "at-fam-old", "aud", "fid-fam", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-fam-old: %v", err)
	}
	if err := rts.Revoke("rt-fam-old"); err != nil {
		t.Fatalf("Revoke rt-fam-old: %v", err)
	}
	if err := rts.Save("rt-fam-new", "at-fam-new", "aud", "fid-fam", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-fam-new: %v", err)
	}
	if got, err := rts.RevokeFamily("fid-fam"); err != nil || got != "at-fam-new" {
		t.Errorf("RevokeFamily: got (%q, %v), want (%q, nil)", got, err, "at-fam-new")
	}
	// No pointer for a family that was never Saved -> ("", nil).
	if got, err := rts.RevokeFamily("fid-no-such-family"); err != nil || got != "" {
		t.Errorf("RevokeFamily on unknown family: got (%q, %v), want (\"\", nil)", got, err)
	}
	// Empty familyID is a permanent no-op: never tombstoned, never has a
	// pointer (Save never associates a row with "").
	if got, err := rts.RevokeFamily(""); err != nil || got != "" {
		t.Errorf("RevokeFamily(\"\"): got (%q, %v), want (\"\", nil)", got, err)
	}
	if err := rts.Save("rt-no-family", "at", "aud", "", time.Now().Add(time.Hour)); err != nil {
		t.Errorf("Save with empty familyID: got err=%v, want nil", err)
	}

	// RevokeFamily tombstones familyID: a subsequent Save for a *different*
	// refresh token in the same family must be rejected with
	// ErrRefreshTokenFamilyRevoked, closing the race where a rotation
	// in-flight when /revoke runs would otherwise resurrect the family with
	// a fresh, non-revoked row (thread-owl review, PR #195).
	if err := rts.Save("rt-tomb-1", "at-tomb-1", "aud", "fid-tomb", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save rt-tomb-1: %v", err)
	}
	if _, err := rts.RevokeFamily("fid-tomb"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if err := rts.Save("rt-tomb-2", "at-tomb-2", "aud", "fid-tomb", time.Now().Add(time.Hour)); !errors.Is(err, ErrRefreshTokenFamilyRevoked) {
		t.Errorf("Save into revoked family: got err=%v, want ErrRefreshTokenFamilyRevoked", err)
	}
	// The blocked Save must not have written a row.
	if _, _, _, _, ok := rts.Lookup("rt-tomb-2"); ok {
		t.Error("Save into revoked family must not create a row despite returning an error")
	}
	// RevokeFamily on a familyID with no existing rows still tombstones it
	// (a rotation could otherwise race the very first Save for a brand-new
	// family and slip in before any row exists to revoke).
	if _, err := rts.RevokeFamily("fid-tomb-empty"); err != nil {
		t.Fatalf("RevokeFamily (no rows): %v", err)
	}
	if err := rts.Save("rt-tomb-empty", "at", "aud", "fid-tomb-empty", time.Now().Add(time.Hour)); !errors.Is(err, ErrRefreshTokenFamilyRevoked) {
		t.Errorf("Save into family revoked before any row existed: got err=%v, want ErrRefreshTokenFamilyRevoked", err)
	}
}

// ── memRefreshTokenStore ──────────────────────────────────────────────────────

func TestMemRefreshTokenStore(t *testing.T) {
	testRefreshTokenStoreContract(t, NewMemRefreshTokenStore())
}

// ── fileRefreshTokenStore ─────────────────────────────────────────────────────

func tempRefreshStorePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "tokens.json.refresh")
}

func TestFileRefreshTokenStore(t *testing.T) {
	rts, err := NewFileRefreshTokenStore(tempRefreshStorePath(t))
	if err != nil {
		t.Fatalf("NewFileRefreshTokenStore: %v", err)
	}
	testRefreshTokenStoreContract(t, rts)
}

// TestFileRefreshTokenStorePersistence is the core regression test for issue #33:
// refresh tokens must survive a process restart (simulated by reloading from the
// same file path).
func TestFileRefreshTokenStorePersistence(t *testing.T) {
	path := tempRefreshStorePath(t)

	rts1, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileRefreshTokenStore: %v", err)
	}
	if err := rts1.Save("persist-rt", "access-tok-persist", "https://gw.example/mcp", "fid-persist", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from same path — simulates container restart.
	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	accessTok, audience, _, _, ok := rts2.Lookup("persist-rt")
	if !ok {
		t.Fatal("after reload: expected hit for previously saved refresh token")
	}
	if accessTok != "access-tok-persist" {
		t.Errorf("after reload: accessToken got %q, want %q", accessTok, "access-tok-persist")
	}
	if audience != "https://gw.example/mcp" {
		t.Errorf("after reload: audience got %q", audience)
	}
}

// TestFileRefreshTokenStoreExpiredNotLoaded verifies that expired refresh tokens
// written before a reload do not surface after the reload's startup sweep.
func TestFileRefreshTokenStoreExpiredNotLoaded(t *testing.T) {
	path := tempRefreshStorePath(t)

	rts1, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileRefreshTokenStore: %v", err)
	}
	if err := rts1.Save("expired-rt", "access-tok-old", "", "fid-old", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload: startup sweep should discard the expired entry.
	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	if _, _, _, _, ok := rts2.Lookup("expired-rt"); ok {
		t.Error("after reload: expired refresh token should not be returned")
	}
}

// TestFileRefreshTokenStoreFilePermissions verifies the file is written with
// mode 0600 on Unix systems.
func TestFileRefreshTokenStoreFilePermissions(t *testing.T) {
	if isWindows() {
		t.Skip("file permission bits not enforced on Windows")
	}
	path := tempRefreshStorePath(t)
	rts, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileRefreshTokenStore: %v", err)
	}
	if err := rts.Save("rt", "at", "", "fid-perm", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file permissions: got %04o, want 0600", perm)
	}
}

// TestFileRefreshTokenStoreParentComponentIsFile verifies that
// NewFileRefreshTokenStore returns an error when a path component used as a
// parent directory is actually a regular file (triggers a non-ErrNotExist load
// failure).
func TestFileRefreshTokenStoreParentComponentIsFile(t *testing.T) {
	dir := t.TempDir()
	// notADir is a regular file; using it as a directory component produces ENOTDIR.
	notADir := filepath.Join(dir, "notadir.txt")
	if err := os.WriteFile(notADir, []byte("x"), 0o600); err != nil {
		t.Fatalf("setup WriteFile: %v", err)
	}
	path := filepath.Join(notADir, "tokens.json.refresh")
	if _, err := NewFileRefreshTokenStore(path); err == nil {
		t.Fatal("expected error when parent component is a file, got nil")
	}
}

// TestFileRefreshTokenStoreParentDirMissing verifies that
// NewFileRefreshTokenStore returns an error when the parent directory of the
// store path does not exist (stat fails after an ErrNotExist load).
func TestFileRefreshTokenStoreParentDirMissing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent", "tokens.json.refresh")
	if _, err := NewFileRefreshTokenStore(path); err == nil {
		t.Fatal("expected error when parent directory does not exist, got nil")
	}
}

// TestFileRefreshTokenStoreParentNotWritable verifies that
// NewFileRefreshTokenStore returns an error when the parent directory exists
// but is not writable.
// Skipped on Windows where chmod write-bit removal is not reliable.
func TestFileRefreshTokenStoreParentNotWritable(t *testing.T) {
	if isWindows() {
		t.Skip("Unix-only: chmod write-bit removal not reliable on Windows")
	}
	dir := t.TempDir()
	roDir := filepath.Join(dir, "readonly")
	if err := os.Mkdir(roDir, 0o500); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(roDir, 0o700) })
	path := filepath.Join(roDir, "tokens.json.refresh")
	if _, err := NewFileRefreshTokenStore(path); err == nil {
		t.Fatal("expected error for unwritable parent directory, got nil")
	}
}

// TestFileRefreshTokenStoreDeleteMissingKey verifies that Delete on a
// non-existent key returns nil without flushing (the short-circuit path).
func TestFileRefreshTokenStoreDeleteMissingKey(t *testing.T) {
	rts, err := NewFileRefreshTokenStore(tempRefreshStorePath(t))
	if err != nil {
		t.Fatalf("NewFileRefreshTokenStore: %v", err)
	}
	if err := rts.Delete("nonexistent-refresh-token"); err != nil {
		t.Errorf("Delete of missing key: got %v, want nil", err)
	}
}

// TestFileRefreshTokenStoreSweepWritesToDisk verifies that Sweep flushes
// pruned state to disk so the reload doesn't see stale entries.
func TestFileRefreshTokenStoreSweepWritesToDisk(t *testing.T) {
	path := tempRefreshStorePath(t)

	rts1, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileRefreshTokenStore: %v", err)
	}
	if err := rts1.Save("valid-rt", "valid-at", "", "fid-v", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save valid: %v", err)
	}
	if err := rts1.Save("stale-rt", "stale-at", "", "fid-s", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save stale: %v", err)
	}
	if err := rts1.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
	}

	// Reload: only valid-rt should be present.
	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	if _, _, _, _, ok := rts2.Lookup("valid-rt"); !ok {
		t.Error("after sweep+reload: valid refresh token should still be present")
	}
	if _, _, _, _, ok := rts2.Lookup("stale-rt"); ok {
		t.Error("after sweep+reload: stale refresh token should have been removed")
	}
}

// ── error-injecting RefreshTokenStore helpers ─────────────────────────────────

// alwaysFailRefreshStore is a RefreshTokenStore whose Save and Delete methods
// always return an error.  Lookup always misses.  Used to cover error-handling
// paths in Store.CreateRefreshToken, ConsumeRefreshToken, and
// RestoreRefreshToken.
type alwaysFailRefreshStore struct{}

var errInjectedStoreFailure = errors.New("test: injected store failure")

func (f *alwaysFailRefreshStore) Save(_, _, _, _ string, _ time.Time) error {
	return errInjectedStoreFailure
}
func (f *alwaysFailRefreshStore) Lookup(_ string) (string, string, string, time.Time, bool) {
	return "", "", "", time.Time{}, false
}
func (f *alwaysFailRefreshStore) LookupAny(_ string) (string, string, string, time.Time, bool, bool) {
	return "", "", "", time.Time{}, false, false
}
func (f *alwaysFailRefreshStore) Revoke(_ string) error { return nil }
func (f *alwaysFailRefreshStore) RevokeFamily(_ string) (string, error) {
	return "", nil
}
func (f *alwaysFailRefreshStore) SaveNonce(_, _ string) error               { return nil }
func (f *alwaysFailRefreshStore) LookupNonce(_ string) string               { return "" }
func (f *alwaysFailRefreshStore) SaveProviderAccessToken(_, _ string) error { return nil }
func (f *alwaysFailRefreshStore) LookupProviderAccessToken(_ string) string { return "" }
func (f *alwaysFailRefreshStore) SaveProviderRefresh(_, _ string, _ time.Time) error {
	return nil
}
func (f *alwaysFailRefreshStore) LookupProviderRefresh(_ string) (string, time.Time) {
	return "", time.Time{}
}
func (f *alwaysFailRefreshStore) RevokeJTI(_ string, _ time.Time) error     { return nil }
func (f *alwaysFailRefreshStore) IsJTIRevoked(_ string) bool                { return false }
func (f *alwaysFailRefreshStore) Delete(_ string) error                     { return errInjectedStoreFailure }
func (f *alwaysFailRefreshStore) Sweep() error                              { return nil }

// testRefreshTokenStoreReuseDetection exercises LookupAny and RevokeFamily on
// the given RefreshTokenStore.  It is shared across in-memory and file-backed
// implementations.
func testRefreshTokenStoreReuseDetection(t *testing.T, rts RefreshTokenStore) {
	t.Helper()
	exp := time.Now().Add(time.Hour)

	// Save two tokens in the same family.
	if err := rts.Save("rt-a", "at-a", "aud", "fid-one", exp); err != nil {
		t.Fatalf("Save rt-a: %v", err)
	}
	if err := rts.Save("rt-b", "at-b", "aud", "fid-one", exp); err != nil {
		t.Fatalf("Save rt-b: %v", err)
	}

	// Simulate rotation: delete rt-a (reserve it).
	if err := rts.Delete("rt-a"); err != nil {
		t.Fatalf("Delete rt-a: %v", err)
	}

	// Lookup must miss for deleted (not expired) rt-a.
	if _, _, _, _, ok := rts.Lookup("rt-a"); ok {
		t.Error("Lookup: expected miss for deleted rt-a")
	}

	// LookupAny must also miss because the entry was hard-deleted (not just revoked).
	if _, _, _, _, _, ok := rts.LookupAny("rt-a"); ok {
		t.Error("LookupAny: expected miss for hard-deleted rt-a")
	}

	// Save a token then revoke the family — rt-b must become inaccessible via Lookup.
	if _, err := rts.RevokeFamily("fid-one"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if _, _, _, _, ok := rts.Lookup("rt-b"); ok {
		t.Error("Lookup: expected miss for rt-b after RevokeFamily")
	}
	// LookupAny must still find rt-b (as revoked=true) until it expires.
	_, _, fid, _, revoked, ok := rts.LookupAny("rt-b")
	if !ok {
		t.Error("LookupAny: expected hit for revoked rt-b")
	}
	if !revoked {
		t.Error("LookupAny: expected revoked=true for rt-b after RevokeFamily")
	}
	if fid != "fid-one" {
		t.Errorf("LookupAny: familyID got %q, want %q", fid, "fid-one")
	}
}

func TestMemRefreshTokenStoreReuseDetection(t *testing.T) {
	testRefreshTokenStoreReuseDetection(t, NewMemRefreshTokenStore())
}

func TestFileRefreshTokenStoreReuseDetection(t *testing.T) {
	rts, err := NewFileRefreshTokenStore(tempRefreshStorePath(t))
	if err != nil {
		t.Fatalf("NewFileRefreshTokenStore: %v", err)
	}
	testRefreshTokenStoreReuseDetection(t, rts)
}

// TestFileRefreshTokenStoreRevokedPersists verifies that the revoked flag
// survives a store reload (process restart simulation).
func TestFileRefreshTokenStoreRevokedPersists(t *testing.T) {
	path := tempRefreshStorePath(t)
	rts1, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("initial NewFileRefreshTokenStore: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	if err := rts1.Save("rt-rv", "at-rv", "aud", "fid-rv", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := rts1.RevokeFamily("fid-rv"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}

	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	if _, _, _, _, ok := rts2.Lookup("rt-rv"); ok {
		t.Error("after reload: revoked token must not be returned by Lookup")
	}
	_, _, _, _, revoked, ok := rts2.LookupAny("rt-rv")
	if !ok {
		t.Error("after reload: revoked token must still be findable via LookupAny")
	}
	if !revoked {
		t.Error("after reload: revoked flag must be persisted")
	}
}

// TestCreateRefreshTokenSaveError verifies that CreateRefreshToken returns an
// error when the underlying RefreshTokenStore.Save call fails.
func TestCreateRefreshTokenSaveError(t *testing.T) {
	store := NewStore(time.Minute, time.Minute, NewMemTokenStore(),
		WithRefreshTokenStore(&alwaysFailRefreshStore{}))
	_, err := store.CreateRefreshToken("access-tok", "https://gw.example/mcp", "fid-1", time.Minute)
	if err == nil {
		t.Fatal("expected Save error, got nil")
	}
}

// TestConsumeRefreshTokenDeleteError verifies that ConsumeRefreshToken logs a
// warning and does not panic when the underlying Delete call fails.
func TestConsumeRefreshTokenDeleteError(t *testing.T) {
	store := NewStore(time.Minute, time.Minute, NewMemTokenStore(),
		WithRefreshTokenStore(&alwaysFailRefreshStore{}))
	// Delete always fails; ConsumeRefreshToken must log and return without panicking.
	store.ConsumeRefreshToken("refresh-tok")
}

// TestRestoreRefreshTokenSaveError verifies that RestoreRefreshToken logs a
// warning and does not panic when the underlying Save call fails.
func TestRestoreRefreshTokenSaveError(t *testing.T) {
	store := NewStore(time.Minute, time.Minute, NewMemTokenStore(),
		WithRefreshTokenStore(&alwaysFailRefreshStore{}))
	// Save always fails; RestoreRefreshToken must log and return without panicking.
	store.RestoreRefreshToken("refresh-tok", "access-tok", "https://gw.example/mcp", "fid-1", time.Now().Add(time.Hour))
}
