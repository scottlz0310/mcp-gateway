package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func tempSQLitePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "tokens.refresh.db")
}

func newTestSQLiteStore(t *testing.T) RefreshTokenStore {
	t.Helper()
	rts, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	return rts
}

func TestSQLiteRefreshTokenStoreContract(t *testing.T) {
	testRefreshTokenStoreContract(t, newTestSQLiteStore(t))
}

func TestSQLiteRefreshTokenStoreReuseDetection(t *testing.T) {
	testRefreshTokenStoreReuseDetection(t, newTestSQLiteStore(t))
}

func closeSQLiteStore(t *testing.T, rts RefreshTokenStore) {
	t.Helper()
	if c, ok := rts.(*sqliteRefreshTokenStore); ok {
		t.Cleanup(func() { _ = c.Close() })
	}
}

// TestSQLiteRefreshTokenStorePersistence verifies that entries survive a store
// reopen (process-restart simulation).
func TestSQLiteRefreshTokenStorePersistence(t *testing.T) {
	path := tempSQLitePath(t)
	exp := time.Now().Add(time.Hour)

	rts1, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	closeSQLiteStore(t, rts1)
	if err := rts1.Save("rt-persist", "at-persist", "aud", "fid-p", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	rts1.(*sqliteRefreshTokenStore).Close() //nolint — close before reopening

	rts2, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	closeSQLiteStore(t, rts2)
	at, aud, fid, _, ok := rts2.Lookup("rt-persist")
	if !ok {
		t.Fatal("Lookup after reopen: expected hit")
	}
	if at != "at-persist" || aud != "aud" || fid != "fid-p" {
		t.Errorf("Lookup after reopen: got at=%q aud=%q fid=%q", at, aud, fid)
	}
}

// TestSQLiteRefreshTokenStoreRevokedPersists verifies that the revoked flag
// survives a store reopen.
func TestSQLiteRefreshTokenStoreRevokedPersists(t *testing.T) {
	path := tempSQLitePath(t)

	rts1, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	exp := time.Now().Add(time.Hour)
	if err := rts1.Save("rt-rv", "at-rv", "aud", "fid-rv", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := rts1.RevokeFamily("fid-rv"); err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	rts1.(*sqliteRefreshTokenStore).Close() //nolint — close before reopening

	rts2, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	closeSQLiteStore(t, rts2)
	if _, _, _, _, ok := rts2.Lookup("rt-rv"); ok {
		t.Error("after reopen: revoked token must not be returned by Lookup")
	}
	_, _, _, _, revoked, ok := rts2.LookupAny("rt-rv")
	if !ok {
		t.Error("after reopen: revoked token must still be findable via LookupAny")
	}
	if !revoked {
		t.Error("after reopen: revoked flag must be persisted")
	}
}

// TestMigrateFileRefreshTokenStore verifies that entries from a legacy
// tokens.json.refresh are imported into the SQLite store and the source file
// is renamed to .migrated.
func TestMigrateFileRefreshTokenStore(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json.refresh")

	exp := time.Now().Add(time.Hour)
	entries := map[string]fileRTEntry{
		tokenKey("rt-legacy-a"): {AccessToken: "at-a", Audience: "aud-a", FamilyID: "fid-a", ExpiresAt: exp},
		tokenKey("rt-legacy-b"): {AccessToken: "at-b", Audience: "aud-b", FamilyID: "fid-b", ExpiresAt: exp, Revoked: true},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(legacyPath, data, 0o600); err != nil {
		t.Fatalf("writing legacy file: %v", err)
	}

	dst, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	if err := migrateFileRefreshTokenStore(legacyPath, dst); err != nil {
		t.Fatalf("migrateFileRefreshTokenStore: %v", err)
	}

	// Legacy file should be renamed.
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("legacy file should have been renamed, but still exists")
	}
	if _, err := os.Stat(legacyPath + ".migrated"); err != nil {
		t.Errorf(".migrated file not found: %v", err)
	}

	// Active token (rt-legacy-a) must be accessible via Lookup.
	at, aud, fid, _, ok := dst.Lookup("rt-legacy-a")
	if !ok {
		t.Fatal("Lookup rt-legacy-a: expected hit after migration")
	}
	if at != "at-a" || aud != "aud-a" || fid != "fid-a" {
		t.Errorf("rt-legacy-a: got at=%q aud=%q fid=%q", at, aud, fid)
	}

	// Revoked token (rt-legacy-b) must not appear in Lookup but must be in LookupAny.
	if _, _, _, _, ok := dst.Lookup("rt-legacy-b"); ok {
		t.Error("Lookup rt-legacy-b: expected miss (revoked)")
	}
	_, _, _, _, revoked, ok := dst.LookupAny("rt-legacy-b")
	if !ok {
		t.Error("LookupAny rt-legacy-b: expected hit (revoked entry)")
	}
	if !revoked {
		t.Error("LookupAny rt-legacy-b: expected revoked=true")
	}
}

// TestMigrateFileRefreshTokenStoreNoFile verifies that migration is a no-op
// when the legacy file does not exist.
func TestMigrateFileRefreshTokenStoreNoFile(t *testing.T) {
	dst, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	if err := migrateFileRefreshTokenStore(filepath.Join(t.TempDir(), "nonexistent"), dst); err != nil {
		t.Errorf("expected nil for missing file, got %v", err)
	}
}

// TestMigrateFileRefreshTokenStoreEmptyFile verifies that an empty legacy file
// is renamed to .migrated without error.
func TestMigrateFileRefreshTokenStoreEmptyFile(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json.refresh")
	if err := os.WriteFile(legacyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}
	dst, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	if err := migrateFileRefreshTokenStore(legacyPath, dst); err != nil {
		t.Fatalf("migrateFileRefreshTokenStore: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("empty legacy file should have been renamed")
	}
	if _, err := os.Stat(legacyPath + ".migrated"); err != nil {
		t.Errorf(".migrated file not found: %v", err)
	}
}

// TestSQLiteRefreshTokenStoreRevoke verifies that Revoke marks a specific token
// as revoked without affecting sibling tokens in the same family.
func TestSQLiteRefreshTokenStoreRevoke(t *testing.T) {
	rts := newTestSQLiteStore(t)
	exp := time.Now().Add(time.Hour)

	if err := rts.Save("rt-a", "at-a", "aud", "fam", exp); err != nil {
		t.Fatalf("Save rt-a: %v", err)
	}
	if err := rts.Save("rt-b", "at-b", "aud", "fam", exp); err != nil {
		t.Fatalf("Save rt-b: %v", err)
	}

	if err := rts.Revoke("rt-a"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}

	// Revoked token must not be returned by Lookup.
	if _, _, _, _, ok := rts.Lookup("rt-a"); ok {
		t.Error("Lookup rt-a: expected miss after Revoke")
	}
	// LookupAny must still find it with revoked=true.
	_, _, _, _, revoked, ok := rts.LookupAny("rt-a")
	if !ok {
		t.Error("LookupAny rt-a: expected hit after Revoke")
	}
	if !revoked {
		t.Error("LookupAny rt-a: expected revoked=true")
	}

	// Sibling token in the same family must be unaffected.
	if _, _, _, _, ok := rts.Lookup("rt-b"); !ok {
		t.Error("Lookup rt-b: sibling must remain accessible after Revoke(rt-a)")
	}
}
