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

// TestOpenSQLiteTokenDBChmodsWALSideFiles verifies that the -wal/-shm side
// files WAL mode creates alongside the main database also get the owner-only
// permission — not just the main file (thread-owl review, PR #196): those
// side files can contain token data mid-transaction, so leaving them at the
// process umask would defeat the confidentiality the main file's 0600 is
// meant to provide. Skipped on Windows where permission bits are not
// enforced (see the isWindows() pattern used by the other *FilePermissions
// tests in this package).
//
// Whether -wal/-shm exist at all by the time openSQLiteTokenDB returns is a
// SQLite-driver/platform implementation detail (observed: present on
// Windows, absent on Linux CI for a freshly-created, otherwise-empty
// database — thread-owl re-review, PR #196 run 28655143021), matching the
// chmod loop's own best-effort contract (os.IsNotExist is not an error). So
// this only asserts the permission on side files that do exist; the main
// database file is always expected to exist and be checked unconditionally.
func TestOpenSQLiteTokenDBChmodsWALSideFiles(t *testing.T) {
	if isWindows() {
		t.Skip("file permission bits not enforced on Windows")
	}
	path := tempSQLitePath(t)
	db, err := openSQLiteTokenDB(path)
	if err != nil {
		t.Fatalf("openSQLiteTokenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	info, statErr := os.Stat(path)
	if statErr != nil {
		t.Fatalf("stat %q: %v", path, statErr)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("%s: mode = %o, want 0600", path, perm)
	}

	for _, suffix := range []string{"-wal", "-shm"} {
		p := path + suffix
		info, statErr := os.Stat(p)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				t.Logf("%s: not materialised by this SQLite build/platform at this point; skipping permission check", p)
				continue
			}
			t.Fatalf("stat %q: %v", p, statErr)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Errorf("%s: mode = %o, want 0600", p, perm)
		}
	}
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

// TestSQLiteRefreshTokenStoreProviderRefreshPersists verifies that the
// provider refresh token and access-token expiry (builtin-mode rotation,
// #190, recovered via SaveProviderRefresh/LookupProviderRefresh) survive a
// store reopen.
func TestSQLiteRefreshTokenStoreProviderRefreshPersists(t *testing.T) {
	path := tempSQLitePath(t)
	exp := time.Now().Add(time.Hour)
	prExpiry := time.Now().Add(8 * time.Hour).Truncate(time.Second)

	rts1, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	closeSQLiteStore(t, rts1)
	if err := rts1.Save("rt-prt-persist", "jwt-persist", "aud", "fid-prt", exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := rts1.SaveProviderRefresh("rt-prt-persist", "ghr_persist1", prExpiry); err != nil {
		t.Fatalf("SaveProviderRefresh: %v", err)
	}
	rts1.(*sqliteRefreshTokenStore).Close() //nolint — close before reopening

	rts2, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	closeSQLiteStore(t, rts2)
	gotPRT, gotPRExpiry := rts2.LookupProviderRefresh("rt-prt-persist")
	if gotPRT != "ghr_persist1" {
		t.Errorf("LookupProviderRefresh after reopen: providerRefreshToken got %q, want %q", gotPRT, "ghr_persist1")
	}
	if !gotPRExpiry.Equal(prExpiry) {
		t.Errorf("LookupProviderRefresh after reopen: providerAccessExpiry got %v, want %v", gotPRExpiry, prExpiry)
	}
}

// TestSQLiteRefreshTokenStoreProviderRefreshColumnMigration verifies that
// opening a database created before the provider_refresh_token/
// provider_access_expiry columns existed does not fail, and that the columns
// become usable afterward (idempotent ALTER TABLE ADD COLUMN).
func TestSQLiteRefreshTokenStoreProviderRefreshColumnMigration(t *testing.T) {
	path := tempSQLitePath(t)

	// Simulate a pre-#190 database: create the table without the
	// provider_refresh_token/provider_access_expiry columns.
	preSchema := `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash   TEXT    PRIMARY KEY,
	access_token TEXT    NOT NULL,
	audience     TEXT    NOT NULL DEFAULT '',
	family_id    TEXT    NOT NULL DEFAULT '',
	expires_at   INTEGER NOT NULL,
	revoked      INTEGER NOT NULL DEFAULT 0,
	nonce        TEXT    NOT NULL DEFAULT '',
	provider_access_token TEXT NOT NULL DEFAULT ''
);`
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on")
	if err != nil {
		t.Fatalf("opening raw sqlite db: %v", err)
	}
	if _, err := db.Exec(preSchema); err != nil {
		t.Fatalf("creating pre-migration schema: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("closing raw sqlite db: %v", err)
	}

	// NewSQLiteRefreshTokenStore must migrate the schema without error and
	// the new columns must be immediately usable.
	rts, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore on pre-migration db: %v", err)
	}
	closeSQLiteStore(t, rts)
	exp := time.Now().Add(time.Hour)
	prExpiry := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	if err := rts.Save("rt-migrated", "at-migrated", "aud", "fid-migrated", exp); err != nil {
		t.Fatalf("Save on migrated schema: %v", err)
	}
	if err := rts.SaveProviderRefresh("rt-migrated", "ghr_migrated", prExpiry); err != nil {
		t.Fatalf("SaveProviderRefresh on migrated schema: %v", err)
	}
	gotPRT, gotPRExpiry := rts.LookupProviderRefresh("rt-migrated")
	if gotPRT != "ghr_migrated" {
		t.Errorf("LookupProviderRefresh on migrated schema: got %q, want %q", gotPRT, "ghr_migrated")
	}
	if !gotPRExpiry.Equal(prExpiry) {
		t.Errorf("LookupProviderRefresh on migrated schema: expiry got %v, want %v", gotPRExpiry, prExpiry)
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

// TestMigrateFileRefreshTokenStoreBackfillsFamilyPointer verifies that a
// legacy family which had already rotated once (an old revoked row plus a
// current non-revoked row for the same family_id) resolves to its current
// access token via RevokeFamily immediately after migration — legacy rows
// are inserted directly into refresh_tokens, bypassing Save, so
// family_current_access_token would otherwise stay empty for them
// (thread-owl review round 3, PR #195).
func TestMigrateFileRefreshTokenStoreBackfillsFamilyPointer(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json.refresh")

	exp := time.Now().Add(time.Hour)
	entries := map[string]fileRTEntry{
		tokenKey("rt-legacy-old"):     {AccessToken: "at-legacy-old", Audience: "aud", FamilyID: "fid-legacy", ExpiresAt: exp, Revoked: true},
		tokenKey("rt-legacy-current"): {AccessToken: "at-legacy-current", Audience: "aud", FamilyID: "fid-legacy", ExpiresAt: exp},
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

	current, err := dst.RevokeFamily("fid-legacy")
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if current != "at-legacy-current" {
		t.Errorf("RevokeFamily after migration: got %q, want %q (the non-revoked legacy row, not the stale one)", current, "at-legacy-current")
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

// TestSQLiteRefreshTokenStoreBackfillsFamilyPointerOnReopen verifies that
// reopening a database whose refresh_tokens rows predate the
// family_current_access_token feature (inserted directly, bypassing Save)
// backfills the pointer from the existing non-revoked row — otherwise a
// family that had already rotated before an upgrade would resolve to no
// current access token (or handler.go's stale fallback) on the first POST
// /revoke after upgrading (thread-owl review round 3, PR #195).
func TestSQLiteRefreshTokenStoreBackfillsFamilyPointerOnReopen(t *testing.T) {
	path := tempSQLitePath(t)

	rts1, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	sq1 := rts1.(*sqliteRefreshTokenStore)

	// Simulate rows that predate the pointer feature: insert directly into
	// refresh_tokens, bypassing Save (which would have populated
	// family_current_access_token on its own).
	exp := time.Now().Add(time.Hour).Unix()
	if _, err := sq1.db.Exec(
		`INSERT INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 1)`,
		tokenKey("rt-legacy-old"), "at-legacy-old", "aud", "fid-legacy", exp,
	); err != nil {
		t.Fatalf("seed old row: %v", err)
	}
	if _, err := sq1.db.Exec(
		`INSERT INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked) VALUES (?, ?, ?, ?, ?, 0)`,
		tokenKey("rt-legacy-current"), "at-legacy-current", "aud", "fid-legacy", exp,
	); err != nil {
		t.Fatalf("seed current row: %v", err)
	}
	var count int
	if err := sq1.db.QueryRow(
		`SELECT COUNT(*) FROM family_current_access_token WHERE family_id = ?`, "fid-legacy",
	).Scan(&count); err != nil {
		t.Fatalf("querying pointer count: %v", err)
	}
	if count != 0 {
		t.Fatalf("setup: expected no pointer before reopen, got %d", count)
	}
	if err := sq1.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen: NewSQLiteRefreshTokenStore must backfill the pointer from the
	// pre-existing non-revoked row.
	rts2, err := NewSQLiteRefreshTokenStore(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	closeSQLiteStore(t, rts2)

	current, err := rts2.RevokeFamily("fid-legacy")
	if err != nil {
		t.Fatalf("RevokeFamily: %v", err)
	}
	if current != "at-legacy-current" {
		t.Errorf("RevokeFamily after backfill-on-reopen: got %q, want %q", current, "at-legacy-current")
	}
}

// ── SQLite TokenStore ────────────────────────────────────────────────────────

// newTestSQLiteTokenStores opens a shared in-memory database and registers
// cleanup for the shared handle.
func newTestSQLiteTokenStores(t *testing.T) (TokenStore, RefreshTokenStore) {
	t.Helper()
	ts, rts, err := NewSQLiteTokenStores(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteTokenStores: %v", err)
	}
	t.Cleanup(func() { _ = ts.(*sqliteTokenStore).Close() })
	return ts, rts
}

func TestSQLiteTokenStoreContract(t *testing.T) {
	ts, _ := newTestSQLiteTokenStores(t)
	testTokenStoreContract(t, ts)
}

func TestSQLiteRefreshTokenStoreContractOnSharedDB(t *testing.T) {
	_, rts := newTestSQLiteTokenStores(t)
	testRefreshTokenStoreContract(t, rts)
}

// TestSQLiteTokenStorePersistence verifies that every TokenRecord field
// round-trips through a store reopen (process-restart simulation), including
// the zero ProviderAccessExpiry ("no expiry hint") sentinel.
func TestSQLiteTokenStorePersistence(t *testing.T) {
	path := tempSQLitePath(t)
	exp := time.Now().Add(time.Hour)
	pae := time.Now().Add(8 * time.Hour).Truncate(time.Second)

	ts1, _, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := ts1.Save("tok-full", "alice", []string{"https://gw.example/mcp"}, exp); err != nil {
		t.Fatalf("Save tok-full: %v", err)
	}
	if err := ts1.SaveProviderAccessToken("tok-full", "gho_persist"); err != nil {
		t.Fatalf("SaveProviderAccessToken: %v", err)
	}
	if err := ts1.SaveProviderRefresh("tok-full", "ghr_persist", pae); err != nil {
		t.Fatalf("SaveProviderRefresh: %v", err)
	}
	if err := ts1.SaveNonce("tok-full", "nonce-persist"); err != nil {
		t.Fatalf("SaveNonce: %v", err)
	}
	if err := ts1.SaveJti("tok-full", "jti-persist"); err != nil {
		t.Fatalf("SaveJti: %v", err)
	}
	// Second entry: provider refresh saved without an expiry hint — must come
	// back as the zero time, not Unix(0).
	if err := ts1.Save("tok-nohint", "bob", nil, exp); err != nil {
		t.Fatalf("Save tok-nohint: %v", err)
	}
	if err := ts1.SaveProviderRefresh("tok-nohint", "ghr_nohint", time.Time{}); err != nil {
		t.Fatalf("SaveProviderRefresh (zero expiry): %v", err)
	}
	if err := ts1.(*sqliteTokenStore).Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	ts2, _, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	t.Cleanup(func() { _ = ts2.(*sqliteTokenStore).Close() })
	rec, ok := ts2.Lookup("tok-full")
	if !ok {
		t.Fatal("Lookup tok-full after reopen: expected hit")
	}
	if rec.Subject != "alice" {
		t.Errorf("Subject: got %q, want %q", rec.Subject, "alice")
	}
	if !rec.HasAudience("https://gw.example/mcp") {
		t.Errorf("Audiences: got %#v, want https://gw.example/mcp", rec.Audiences)
	}
	if rec.ProviderAccessToken != "gho_persist" {
		t.Errorf("ProviderAccessToken: got %q, want %q", rec.ProviderAccessToken, "gho_persist")
	}
	if rec.ProviderRefreshToken != "ghr_persist" {
		t.Errorf("ProviderRefreshToken: got %q, want %q", rec.ProviderRefreshToken, "ghr_persist")
	}
	if !rec.ProviderAccessExpiry.Equal(pae) {
		t.Errorf("ProviderAccessExpiry: got %v, want %v", rec.ProviderAccessExpiry, pae)
	}
	if rec.Nonce != "nonce-persist" {
		t.Errorf("Nonce: got %q, want %q", rec.Nonce, "nonce-persist")
	}
	if rec.Jti != "jti-persist" {
		t.Errorf("Jti: got %q, want %q", rec.Jti, "jti-persist")
	}

	recNoHint, ok := ts2.Lookup("tok-nohint")
	if !ok {
		t.Fatal("Lookup tok-nohint after reopen: expected hit")
	}
	if !recNoHint.ProviderAccessExpiry.IsZero() {
		t.Errorf("ProviderAccessExpiry: got %v, want zero time", recNoHint.ProviderAccessExpiry)
	}
}

// TestSQLiteTokenStoreMarkRotationFailedPersists verifies the restart
// durability of RotationPermanentlyFailed — the property that keeps a dead
// bearer out of the subject index after a gateway restart.
func TestSQLiteTokenStoreMarkRotationFailedPersists(t *testing.T) {
	path := tempSQLitePath(t)

	ts1, _, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := ts1.Save("tok-dead", "alice", nil, time.Now().Add(time.Hour)); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := ts1.MarkRotationFailed("tok-dead"); err != nil {
		t.Fatalf("MarkRotationFailed: %v", err)
	}
	if err := ts1.(*sqliteTokenStore).Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	ts2, _, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	t.Cleanup(func() { _ = ts2.(*sqliteTokenStore).Close() })
	rec, ok := ts2.Lookup("tok-dead")
	if !ok {
		t.Fatal("Lookup after reopen: expected hit")
	}
	if !rec.RotationPermanentlyFailed {
		t.Error("RotationPermanentlyFailed must survive a reopen")
	}
}

// TestSQLiteTokenStoresShareDatabase verifies that the TokenStore and
// RefreshTokenStore returned by NewSQLiteTokenStores write into the same
// database file and both survive a reopen through it.
func TestSQLiteTokenStoresShareDatabase(t *testing.T) {
	path := tempSQLitePath(t)
	exp := time.Now().Add(time.Hour)

	ts1, rts1, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 1: %v", err)
	}
	if err := ts1.Save("at-shared", "alice", nil, exp); err != nil {
		t.Fatalf("TokenStore.Save: %v", err)
	}
	if err := rts1.Save("rt-shared", "at-shared", "aud", "fid-shared", exp); err != nil {
		t.Fatalf("RefreshTokenStore.Save: %v", err)
	}
	if err := ts1.(*sqliteTokenStore).Close(); err != nil {
		t.Fatalf("close 1: %v", err)
	}

	ts2, rts2, err := NewSQLiteTokenStores(path)
	if err != nil {
		t.Fatalf("open 2: %v", err)
	}
	t.Cleanup(func() { _ = ts2.(*sqliteTokenStore).Close() })
	if _, ok := ts2.Lookup("at-shared"); !ok {
		t.Error("TokenStore entry must survive reopen of the shared database")
	}
	if _, _, _, _, ok := rts2.Lookup("rt-shared"); !ok {
		t.Error("RefreshTokenStore entry must survive reopen of the shared database")
	}
}

// TestMigrateFileTokenStore verifies that entries from a legacy tokens.json
// are imported into the SQLite store with all fields intact and the source
// file is renamed to .migrated.
func TestMigrateFileTokenStore(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json")

	exp := time.Now().Add(time.Hour)
	pae := time.Now().Add(8 * time.Hour).Truncate(time.Second)
	entries := map[string]fileEntry{
		tokenKey("tok-legacy-full"): {
			Subject:              "alice",
			Audiences:            []string{"https://gw.example/mcp"},
			ExpiresAt:            exp,
			ProviderAccessToken:  "gho_legacy",
			ProviderRefreshToken: "ghr_legacy",
			ProviderAccessExpiry: pae,
			RotationFailed:       true,
			Nonce:                "nonce-legacy",
			Jti:                  "jti-legacy",
		},
		tokenKey("tok-legacy-min"): {Subject: "bob", ExpiresAt: exp},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(legacyPath, data, 0o600); err != nil {
		t.Fatalf("writing legacy file: %v", err)
	}

	dst, _ := newTestSQLiteTokenStores(t)
	if err := migrateFileTokenStore(legacyPath, dst); err != nil {
		t.Fatalf("migrateFileTokenStore: %v", err)
	}

	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("legacy file should have been renamed, but still exists")
	}
	if _, err := os.Stat(legacyPath + ".migrated"); err != nil {
		t.Errorf(".migrated file not found: %v", err)
	}

	rec, ok := dst.Lookup("tok-legacy-full")
	if !ok {
		t.Fatal("Lookup tok-legacy-full: expected hit after migration")
	}
	if rec.Subject != "alice" {
		t.Errorf("Subject: got %q, want %q", rec.Subject, "alice")
	}
	if !rec.HasAudience("https://gw.example/mcp") {
		t.Errorf("Audiences: got %#v", rec.Audiences)
	}
	if rec.ProviderAccessToken != "gho_legacy" {
		t.Errorf("ProviderAccessToken: got %q, want %q", rec.ProviderAccessToken, "gho_legacy")
	}
	if rec.ProviderRefreshToken != "ghr_legacy" {
		t.Errorf("ProviderRefreshToken: got %q, want %q", rec.ProviderRefreshToken, "ghr_legacy")
	}
	if !rec.ProviderAccessExpiry.Equal(pae) {
		t.Errorf("ProviderAccessExpiry: got %v, want %v", rec.ProviderAccessExpiry, pae)
	}
	if !rec.RotationPermanentlyFailed {
		t.Error("RotationPermanentlyFailed must survive migration")
	}
	if rec.Nonce != "nonce-legacy" {
		t.Errorf("Nonce: got %q, want %q", rec.Nonce, "nonce-legacy")
	}
	if rec.Jti != "jti-legacy" {
		t.Errorf("Jti: got %q, want %q", rec.Jti, "jti-legacy")
	}

	recMin, ok := dst.Lookup("tok-legacy-min")
	if !ok {
		t.Fatal("Lookup tok-legacy-min: expected hit after migration")
	}
	if recMin.Subject != "bob" || len(recMin.Audiences) != 0 || !recMin.ProviderAccessExpiry.IsZero() {
		t.Errorf("tok-legacy-min: got %+v, want minimal record", recMin)
	}
}

// TestMigrateFileTokenStoreDoesNotOverwrite verifies that INSERT OR IGNORE
// keeps an already-present SQLite row authoritative over the legacy file.
func TestMigrateFileTokenStoreDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json")

	exp := time.Now().Add(time.Hour)
	entries := map[string]fileEntry{
		tokenKey("tok-conflict"): {Subject: "stale-subject", ExpiresAt: exp},
	}
	data, _ := json.Marshal(entries)
	if err := os.WriteFile(legacyPath, data, 0o600); err != nil {
		t.Fatalf("writing legacy file: %v", err)
	}

	dst, _ := newTestSQLiteTokenStores(t)
	if err := dst.Save("tok-conflict", "current-subject", nil, exp); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := migrateFileTokenStore(legacyPath, dst); err != nil {
		t.Fatalf("migrateFileTokenStore: %v", err)
	}
	rec, ok := dst.Lookup("tok-conflict")
	if !ok {
		t.Fatal("Lookup tok-conflict: expected hit")
	}
	if rec.Subject != "current-subject" {
		t.Errorf("Subject: got %q, want the pre-existing SQLite row to win", rec.Subject)
	}
}

// TestMigrateFileTokenStoreEmptyFileRenameError verifies that a rename
// failure on an empty legacy file is surfaced as an error rather than
// silently swallowed (thread-owl review, PR #196): swallowing it would let
// startup proceed while leaving the empty file in place to be re-processed
// (and potentially fail the same way again) on every subsequent restart,
// contradicting the "renamed to .migrated" contract other callers rely on.
func TestMigrateFileTokenStoreEmptyFileRenameError(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(legacyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}
	// Pre-create the .migrated destination as a non-empty directory so
	// renameOverwrite's os.Remove(dst) fails with something other than
	// "not exist", forcing the rename failure down the error path instead of
	// the normal no-op-if-absent path.
	migratedPath := legacyPath + ".migrated"
	if err := os.Mkdir(migratedPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(migratedPath, "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}

	dst, _ := newTestSQLiteTokenStores(t)
	if err := migrateFileTokenStore(legacyPath, dst); err == nil {
		t.Fatal("expected error when the .migrated destination cannot be removed, got nil")
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		t.Errorf("legacy empty file should remain in place after a failed rename: %v", statErr)
	}
}

// TestMigrateFileRefreshTokenStoreEmptyFileRenameError is the
// RefreshTokenStore counterpart of TestMigrateFileTokenStoreEmptyFileRenameError.
func TestMigrateFileRefreshTokenStoreEmptyFileRenameError(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json.refresh")
	if err := os.WriteFile(legacyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}
	migratedPath := legacyPath + ".migrated"
	if err := os.Mkdir(migratedPath, 0o755); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(migratedPath, "blocker"), []byte("x"), 0o600); err != nil {
		t.Fatalf("writing blocker file: %v", err)
	}

	dst, err := NewSQLiteRefreshTokenStore(":memory:")
	if err != nil {
		t.Fatalf("NewSQLiteRefreshTokenStore: %v", err)
	}
	if err := migrateFileRefreshTokenStore(legacyPath, dst); err == nil {
		t.Fatal("expected error when the .migrated destination cannot be removed, got nil")
	}
	if _, statErr := os.Stat(legacyPath); statErr != nil {
		t.Errorf("legacy empty file should remain in place after a failed rename: %v", statErr)
	}
}

// TestMigrateFileTokenStoreNoFile verifies that migration is a no-op when the
// legacy file does not exist.
func TestMigrateFileTokenStoreNoFile(t *testing.T) {
	dst, _ := newTestSQLiteTokenStores(t)
	if err := migrateFileTokenStore(filepath.Join(t.TempDir(), "nonexistent"), dst); err != nil {
		t.Errorf("expected nil for missing file, got %v", err)
	}
}

// TestMigrateFileTokenStoreEmptyFile verifies that an empty legacy file is
// renamed to .migrated without error.
func TestMigrateFileTokenStoreEmptyFile(t *testing.T) {
	dir := t.TempDir()
	legacyPath := filepath.Join(dir, "tokens.json")
	if err := os.WriteFile(legacyPath, []byte{}, 0o600); err != nil {
		t.Fatalf("writing empty file: %v", err)
	}
	dst, _ := newTestSQLiteTokenStores(t)
	if err := migrateFileTokenStore(legacyPath, dst); err != nil {
		t.Fatalf("migrateFileTokenStore: %v", err)
	}
	if _, err := os.Stat(legacyPath); !os.IsNotExist(err) {
		t.Error("empty legacy file should have been renamed")
	}
	if _, err := os.Stat(legacyPath + ".migrated"); err != nil {
		t.Errorf(".migrated file not found: %v", err)
	}
}
