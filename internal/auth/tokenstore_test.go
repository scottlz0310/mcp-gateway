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
	if err := ts.Save("tok1", "alice", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	subj, ok := ts.Lookup("tok1")
	if !ok {
		t.Fatal("Lookup: expected hit after Save")
	}
	if subj != "alice" {
		t.Errorf("Lookup: subject got %q, want %q", subj, "alice")
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
	if err := ts.Save("tok2", "bob", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if _, ok := ts.Lookup("tok2"); ok {
		t.Error("Lookup: expected miss for expired entry")
	}

	// Sweep removes expired entries
	if err := ts.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
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
		if err := ts.Save(token, name, time.Now().Add(time.Hour)); err != nil {
			t.Fatalf("Save %q: %v", token, err)
		}
	}

	for i, want := range []string{"alice", "bob", "carol"} {
		token := string(rune('a' + i))
		got, ok := ts.Lookup(token)
		if !ok {
			t.Fatalf("Lookup %q: expected hit", token)
		}
		if got != want {
			t.Errorf("Lookup %q: got %q, want %q", token, got, want)
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
	if err := ts1.Save("persist-tok", "dave", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from same path — simulates container restart.
	ts2, err := NewFileTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileTokenStore: %v", err)
	}
	subj, ok := ts2.Lookup("persist-tok")
	if !ok {
		t.Fatal("after reload: expected cache hit for previously saved token")
	}
	if subj != "dave" {
		t.Errorf("after reload: subject got %q, want %q", subj, "dave")
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
	if err := ts1.Save("expired-tok", "eve", time.Now().Add(-time.Second)); err != nil {
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
	if err := ts.Save("tok", "frank", time.Now().Add(time.Hour)); err != nil {
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
	if err := ts1.Save("valid-tok", "grace", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save valid token: %v", err)
	}
	if err := ts1.Save("stale-tok", "harry", time.Now().Add(-time.Second)); err != nil {
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
	if err := rts.Save("rt1", "access-tok-1", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, gotExp, ok := rts.Lookup("rt1")
	if !ok {
		t.Fatal("Lookup: expected hit after Save")
	}
	if got != "access-tok-1" {
		t.Errorf("Lookup: accessToken got %q, want %q", got, "access-tok-1")
	}
	if gotExp.IsZero() {
		t.Error("Lookup: expiresAt should not be zero")
	}

	// Lookup — miss for unknown token
	if _, _, ok := rts.Lookup("unknown"); ok {
		t.Error("Lookup: expected miss for unknown token")
	}

	// Delete
	if err := rts.Delete("rt1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, _, ok := rts.Lookup("rt1"); ok {
		t.Error("Lookup: expected miss after Delete")
	}

	// Expired entries are not returned by Lookup
	if err := rts.Save("rt2", "access-tok-2", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if _, _, ok := rts.Lookup("rt2"); ok {
		t.Error("Lookup: expected miss for expired entry")
	}

	// Sweep removes expired entries
	if err := rts.Sweep(); err != nil {
		t.Fatalf("Sweep: %v", err)
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
	if err := rts1.Save("persist-rt", "access-tok-persist", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload from same path — simulates container restart.
	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	accessTok, _, ok := rts2.Lookup("persist-rt")
	if !ok {
		t.Fatal("after reload: expected hit for previously saved refresh token")
	}
	if accessTok != "access-tok-persist" {
		t.Errorf("after reload: accessToken got %q, want %q", accessTok, "access-tok-persist")
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
	if err := rts1.Save("expired-rt", "access-tok-old", time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Reload: startup sweep should discard the expired entry.
	rts2, err := NewFileRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("reloaded NewFileRefreshTokenStore: %v", err)
	}
	if _, _, ok := rts2.Lookup("expired-rt"); ok {
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
	if err := rts.Save("rt", "at", time.Now().Add(time.Hour)); err != nil {
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
	if err := rts1.Save("valid-rt", "valid-at", time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save valid: %v", err)
	}
	if err := rts1.Save("stale-rt", "stale-at", time.Now().Add(-time.Second)); err != nil {
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
	if _, _, ok := rts2.Lookup("valid-rt"); !ok {
		t.Error("after sweep+reload: valid refresh token should still be present")
	}
	if _, _, ok := rts2.Lookup("stale-rt"); ok {
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

func (f *alwaysFailRefreshStore) Save(_, _ string, _ time.Time) error {
	return errInjectedStoreFailure
}
func (f *alwaysFailRefreshStore) Lookup(_ string) (string, time.Time, bool) {
	return "", time.Time{}, false
}
func (f *alwaysFailRefreshStore) Delete(_ string) error { return errInjectedStoreFailure }
func (f *alwaysFailRefreshStore) Sweep() error          { return nil }

// TestCreateRefreshTokenSaveError verifies that CreateRefreshToken returns an
// error when the underlying RefreshTokenStore.Save call fails.
func TestCreateRefreshTokenSaveError(t *testing.T) {
	store := NewStore(time.Minute, time.Minute, NewMemTokenStore(),
		WithRefreshTokenStore(&alwaysFailRefreshStore{}))
	_, err := store.CreateRefreshToken("access-tok", time.Minute)
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
	store.RestoreRefreshToken("refresh-tok", "access-tok", time.Now().Add(time.Hour))
}
