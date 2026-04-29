package auth

import (
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
