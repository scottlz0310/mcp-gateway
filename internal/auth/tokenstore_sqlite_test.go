package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
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

// TestSQLiteRefreshTokenStoreProviderAccessTokenPersists verifies that the
// provider access token (builtin mode's GitHub token, recovered via
// SaveProviderAccessToken/LookupProviderAccessToken) survives a store reopen.
func TestSQLiteRefreshTokenStoreProviderAccessTokenPersists(t *testing.T) {
	path := tempSQLitePath(t)
	exp := time.Now().Add(time.Hour)

	rts1, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	closeSQLiteStore(t, rts1)
	if err := rts1.Save("rt-pat-persist", "jwt-persist", "aud", "fid-pat", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := rts1.SaveProviderAccessToken("rt-pat-persist", "gho_persist1"); err != nil {
		t.Fatalf("SaveProviderAccessToken: %v", err)
	}
	rts1.(*sqliteRefreshTokenStore).Close() //nolint — close before reopening

	rts2, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	closeSQLiteStore(t, rts2)
	if got := rts2.LookupProviderAccessToken("rt-pat-persist"); got != "gho_persist1" {
		t.Errorf("LookupProviderAccessToken after reopen: got %q, want %q", got, "gho_persist1")
	}
}

// TestSQLiteRefreshTokenStoreProviderAccessTokenColumnMigration verifies that
// opening a database created before the provider_access_token column existed
// does not fail, and that the column becomes usable afterward (idempotent
// ALTER TABLE ADD COLUMN).
func TestSQLiteRefreshTokenStoreProviderAccessTokenColumnMigration(t *testing.T) {
	path := tempSQLitePath(t)

	// Simulate a pre-migration database: create the table without the
	// provider_access_token column (as it existed before scottlz0310/mcp-gateway#188).
	preSchema := `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash   TEXT    PRIMARY KEY,
	access_token TEXT    NOT NULL,
	audience     TEXT    NOT NULL DEFAULT '',
	family_id    TEXT    NOT NULL DEFAULT '',
	expires_at   INTEGER NOT NULL,
	revoked      INTEGER NOT NULL DEFAULT 0,
	nonce        TEXT    NOT NULL DEFAULT ''
);`
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatalf("opening raw sqlite db: %v", err)
	}
	if _, err := db.Exec(preSchema); err != nil {
		t.Fatalf("creating pre-migration schema: %v", err)
	}
	if _, err := db.Exec(
		`INSERT INTO refresh_tokens (token_hash, access_token, expires_at) VALUES (?, ?, ?)`,
		tokenKey("rt-premigration"), "jwt-premigration", time.Now().Add(time.Hour).Unix(),
	); err != nil {
		t.Fatalf("inserting pre-migration row: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing raw sqlite db: %v", err)
	}

	// NewSQLiteRefreshTokenStore must migrate the schema without error and
	// leave the pre-existing row's provider_access_token as the column default.
	rts, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore on pre-migration db: %v", err)
	}
	closeSQLiteStore(t, rts)
	if got := rts.LookupProviderAccessToken("rt-premigration"); got != "" {
		t.Errorf("pre-migration row provider_access_token: got %q, want empty default", got)
	}
	if err := rts.SaveProviderAccessToken("rt-premigration", "gho_postmigration"); err != nil {
		t.Fatalf("SaveProviderAccessToken after migration: %v", err)
	}
	if got := rts.LookupProviderAccessToken("rt-premigration"); got != "gho_postmigration" {
		t.Errorf("post-migration write: got %q, want %q", got, "gho_postmigration")
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
	if _, err := rts1.RevokeFamily("fid-rv"); err != nil {
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

// TestSQLiteRefreshTokenStoreIsJTIRevokedFailsClosedOnDBError verifies that
// IsJTIRevoked treats a database error (as opposed to a legitimate "not
// found") as revoked, per the Copilot review finding on PR #195: failing
// open here would let a JWT that really was denylisted keep validating
// whenever the store happens to be unreadable (locked, corrupt, read-only).
func TestSQLiteRefreshTokenStoreIsJTIRevokedFailsClosedOnDBError(t *testing.T) {
	rts, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	sq := rts.(*sqliteRefreshTokenStore)

	// Baseline: an absent jti (sql.ErrNoRows path) is correctly "not revoked".
	if sq.IsJTIRevoked("never-revoked") {
		t.Fatal("IsJTIRevoked: expected false for an absent jti before simulating a DB error")
	}

	// Force every subsequent query to fail with something other than
	// ErrNoRows by closing the underlying connection.
	if err := sq.db.Close(); err != nil {
		t.Fatalf("closing db: %v", err)
	}

	if !sq.IsJTIRevoked("any-jti") {
		t.Error("IsJTIRevoked: expected true (fail closed) when the database is unreadable")
	}
}

// TestSQLiteRefreshTokenStoreConcurrentRotationVsRevoke stress-tests the
// atomicity between Save (rotation) and RevokeFamily (POST /revoke) for the
// same family, racing many goroutines against a single family to catch any
// interleaving that would let a rotation slip a fresh, non-revoked row (or
// an unaccounted-for family_current_access_token pointer value) past a
// concurrent revocation (thread-owl review, PR #195).
func TestSQLiteRefreshTokenStoreConcurrentRotationVsRevoke(t *testing.T) {
	rts, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	sq := rts.(*sqliteRefreshTokenStore)
	t.Cleanup(func() { _ = sq.Close() })

	const familyID = "fid-race"
	const seedAccessToken = "at-race-0"
	exp := time.Now().Add(time.Hour)
	if err := rts.Save("rt-race-0", seedAccessToken, "aud", familyID, exp); err != nil {
		t.Fatalf("seed Save: %v", err)
	}

	const attempts = 200
	revokeStart := make(chan struct{})
	saveResults := make([]error, attempts)
	// Each attempt writes a distinct access token so a successful Save can be
	// unambiguously identified by value alone (rather than by index, which a
	// racing goroutine cannot correlate to RevokeFamily's returned pointer).
	accessTokens := make([]string, attempts)
	for i := range attempts {
		accessTokens[i] = fmt.Sprintf("at-race-%d", i+1)
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		<-revokeStart
		for i := range attempts {
			rt := fmt.Sprintf("rt-race-%d", i+1)
			saveResults[i] = rts.Save(rt, accessTokens[i], "aud", familyID, exp)
		}
	}()

	close(revokeStart)
	currentAccessToken, err := rts.RevokeFamily(familyID)
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	<-done

	// RevokeFamily's returned pointer must correspond to a write that
	// actually happened — either the seed or one of the Saves that reported
	// success — never an unknown or torn value.
	validValues := map[string]bool{seedAccessToken: true}
	for i, err := range saveResults {
		if err == nil {
			validValues[accessTokens[i]] = true
		} else if !errors.Is(err, ErrRefreshTokenFamilyRevoked) {
			t.Errorf("Save[%d]: unexpected error %v", i, err)
		}
	}
	if currentAccessToken == "" || !validValues[currentAccessToken] {
		t.Errorf("RevokeFamily: returned currentAccessToken %q, want one of the seed or successfully-saved values", currentAccessToken)
	}

	// Once RevokeFamily has returned, the tombstone must stick: no further
	// Save for this family can succeed, so the pointer can never advance
	// past whatever RevokeFamily observed.
	if err := rts.Save("rt-race-post", "at-race-post", "aud", familyID, exp); !errors.Is(err, ErrRefreshTokenFamilyRevoked) {
		t.Errorf("Save after RevokeFamily returned: got err=%v, want ErrRefreshTokenFamilyRevoked", err)
	}
	var pointerAfter string
	if err := sq.db.QueryRow(
		`SELECT access_token FROM family_current_access_token WHERE family_id = ?`, familyID,
	).Scan(&pointerAfter); err != nil {
		t.Fatalf("querying family_current_access_token: %v", err)
	}
	if pointerAfter != currentAccessToken {
		t.Errorf("family_current_access_token after RevokeFamily: got %q, want unchanged %q", pointerAfter, currentAccessToken)
	}
}
