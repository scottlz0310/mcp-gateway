package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteTokenDBSchema = `
-- access_tokens is the primary token store (TokenStore): metadata for
-- validated access tokens, keyed by tokenKey(rawToken) so raw token values
-- never reach disk. audiences is a JSON-encoded string array ('' = none).
-- provider_access_expiry is 0 when the provider gave no expiry hint.
CREATE TABLE IF NOT EXISTS access_tokens (
	token_hash             TEXT    PRIMARY KEY,
	subject                TEXT    NOT NULL DEFAULT '',
	audiences              TEXT    NOT NULL DEFAULT '',
	expires_at             INTEGER NOT NULL,
	provider_access_token  TEXT    NOT NULL DEFAULT '',
	provider_refresh_token TEXT    NOT NULL DEFAULT '',
	provider_access_expiry INTEGER NOT NULL DEFAULT 0,
	rotation_failed        INTEGER NOT NULL DEFAULT 0,
	nonce                  TEXT    NOT NULL DEFAULT '',
	jti                    TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_at_expires ON access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash   TEXT    PRIMARY KEY,
	access_token TEXT    NOT NULL,
	audience     TEXT    NOT NULL DEFAULT '',
	family_id    TEXT    NOT NULL DEFAULT '',
	expires_at   INTEGER NOT NULL,
	revoked      INTEGER NOT NULL DEFAULT 0,
	nonce        TEXT    NOT NULL DEFAULT '',
	provider_access_token  TEXT    NOT NULL DEFAULT '',
	provider_refresh_token TEXT    NOT NULL DEFAULT '',
	provider_access_expiry INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rt_family  ON refresh_tokens (family_id) WHERE revoked = 0;
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens (expires_at);

-- revoked_jti is the denylist for gateway-issued access tokens (builtin
-- mode). expires_at mirrors the token's own exp claim so entries are
-- naturally swept once the JWT would have expired anyway, bounding the
-- table to the set of revoked-but-not-yet-expired tokens.
CREATE TABLE IF NOT EXISTS revoked_jti (
	jti        TEXT    PRIMARY KEY,
	expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_revoked_jti_expires ON revoked_jti (expires_at);

-- revoked_families tombstones a refresh-token family (RFC 6819 §5.2.2.3)
-- permanently, independent of the mutable revoked flag on individual
-- refresh_tokens rows. Save() checks this table so a rotation racing a
-- concurrent RevokeFamily cannot resurrect the family with a fresh,
-- non-revoked row after the revocation appears to have completed. Never
-- swept: family IDs are single-use random strings, so this table only grows
-- with explicit revocations (expected to stay small).
CREATE TABLE IF NOT EXISTS revoked_families (
	family_id  TEXT PRIMARY KEY,
	revoked_at INTEGER NOT NULL
);

-- family_current_access_token tracks, per family, the access token most
-- recently written by a successful Save — independent of whether the
-- refresh_tokens row backing it has since been soft-revoked (e.g.
-- mid-rotation, after the old row is reserved but before the new row's Save
-- runs). RevokeFamily reads this atomically alongside its own tombstone
-- write so POST /revoke can denylist the access token actually in use at
-- the moment of revocation, not a stale predecessor. Swept on the same
-- expires_at basis as refresh_tokens.
CREATE TABLE IF NOT EXISTS family_current_access_token (
	family_id    TEXT PRIMARY KEY,
	access_token TEXT NOT NULL,
	expires_at   INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_family_cat_expires ON family_current_access_token (expires_at);
`

type sqliteRefreshTokenStore struct {
	db *sql.DB
}

// sqlExecer is satisfied by both *sql.DB and *sql.Tx, letting
// backfillFamilyCurrentAccessToken run either as a standalone statement
// (startup) or inside an existing transaction (legacy file migration).
type sqlExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// backfillFamilyCurrentAccessTokenSQL populates family_current_access_token
// for any family that has non-revoked, non-expired refresh_tokens rows but
// no pointer entry yet — i.e. rows that predate this feature (an existing
// database reopened after upgrade) or that were just written directly by
// migrateFileRefreshTokenStore (which inserts into refresh_tokens without
// going through Save, so it never populates the pointer table on its own).
// INSERT OR IGNORE is a no-op for a family that already has a pointer, so
// this never clobbers state Save has correctly been maintaining.
//
// Per family, the backfilled row is the non-revoked one with the latest
// expires_at. Under correct operation at most one non-revoked row exists per
// family at a time (rotation soft-revokes the predecessor before creating
// the successor), so this is unambiguous; the MAX(expires_at) tie-break only
// matters for anomalous pre-existing data, where it is a reasonable
// heuristic (each rotation extends expires_at to a fresh TTL, so the
// non-revoked row with the furthest-out expiry is the most recently rotated
// one).
const backfillFamilyCurrentAccessTokenSQL = `
INSERT OR IGNORE INTO family_current_access_token (family_id, access_token, expires_at)
SELECT r.family_id, r.access_token, r.expires_at
FROM refresh_tokens r
WHERE r.revoked = 0 AND r.family_id != '' AND r.expires_at > ?
  AND r.expires_at = (
    SELECT MAX(r2.expires_at) FROM refresh_tokens r2
    WHERE r2.family_id = r.family_id AND r2.revoked = 0
  )
`

func backfillFamilyCurrentAccessToken(ex sqlExecer) error {
	_, err := ex.Exec(backfillFamilyCurrentAccessTokenSQL, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("backfilling family_current_access_token: %w", err)
	}
	return nil
}

// openSQLiteTokenDB opens (or creates) the shared token database at path,
// initialises the full schema (access_tokens + refresh-token tables), applies
// idempotent column migrations, and enforces owner-only file permissions.
// path may be ":memory:" for in-process testing.
func openSQLiteTokenDB(path string) (*sql.DB, error) {
	// WAL mode for concurrent readers; busy_timeout avoids immediate SQLITE_BUSY.
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening SQLite token store %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite WAL allows 1 writer; serialise via the connection pool
	if _, err := db.Exec(sqliteTokenDBSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising SQLite token store schema: %w", err)
	}
	// Add columns to existing databases created before these fields were
	// introduced. ALTER TABLE ADD COLUMN is idempotent in SQLite when the
	// column already exists (returns "duplicate column name" which we
	// intentionally ignore).
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN nonce TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN provider_access_token TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN provider_refresh_token TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN provider_access_expiry INTEGER NOT NULL DEFAULT 0`)
	// Backfill family_current_access_token for a database that predates this
	// feature — otherwise a family whose only pointer-eligible row exists
	// from before the upgrade would resolve to no current access token on
	// the first POST /revoke after upgrading (see backfillFamilyCurrentAccessTokenSQL).
	if err := backfillFamilyCurrentAccessToken(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising SQLite token store: %w", err)
	}
	if path != ":memory:" {
		// WAL mode can materialise token data into -wal/-shm side files, so the
		// same owner-only permission must apply to them, not just the main file.
		for _, suffix := range [...]string{"", "-wal", "-shm"} {
			if err := os.Chmod(path+suffix, 0o600); err != nil && !os.IsNotExist(err) {
				slog.Warn("SQLite token store chmod failed", "path", path+suffix, "err", err)
			}
		}
	}
	return db, nil
}

// NewSQLiteRefreshTokenStore returns a SQLite-backed RefreshTokenStore.
// path may be ":memory:" for in-process testing.
func NewSQLiteRefreshTokenStore(path string) (RefreshTokenStore, error) {
	db, err := openSQLiteTokenDB(path)
	if err != nil {
		return nil, err
	}
	s := &sqliteRefreshTokenStore{db: db}
	swept, err := s.sweepNow()
	if err != nil {
		slog.Warn("SQLite refresh token store startup sweep failed", "err", err)
	}
	var count int
	_ = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&count)
	slog.Info("SQLite refresh token store opened", "path", path, "entries", count, "swept", swept)
	return s, nil
}

// NewSQLiteTokenStores opens the shared token database at path and returns a
// TokenStore and a RefreshTokenStore backed by the same *sql.DB — one file,
// one writer lock, one transaction boundary for the gateway's whole logical
// token state (issue #191). Closing either store closes the shared handle, so
// callers should close exactly one of them at shutdown (Store.Close does this
// via the RefreshTokenStore). path may be ":memory:" for in-process testing.
func NewSQLiteTokenStores(path string) (TokenStore, RefreshTokenStore, error) {
	db, err := openSQLiteTokenDB(path)
	if err != nil {
		return nil, nil, err
	}
	ts := &sqliteTokenStore{db: db}
	rts := &sqliteRefreshTokenStore{db: db}
	sweptAT, err := ts.sweepNow()
	if err != nil {
		slog.Warn("SQLite token store startup sweep failed", "err", err)
	}
	sweptRT, err := rts.sweepNow()
	if err != nil {
		slog.Warn("SQLite refresh token store startup sweep failed", "err", err)
	}
	var countAT, countRT int
	_ = db.QueryRow("SELECT COUNT(*) FROM access_tokens").Scan(&countAT)
	_ = db.QueryRow("SELECT COUNT(*) FROM refresh_tokens").Scan(&countRT)
	slog.Info("SQLite token store opened", "path", path,
		"access_tokens", countAT, "refresh_tokens", countRT,
		"swept_access", sweptAT, "swept_refresh", sweptRT)
	return ts, rts, nil
}

// Save writes refreshToken's row guarded by a NOT EXISTS check against
// revoked_families, and — inside the same transaction — updates the
// family's family_current_access_token pointer. Wrapping both in one
// transaction means this is atomic with RevokeFamily's own transaction with
// respect to concurrent callers (the store's single DB connection — see
// NewSQLiteRefreshTokenStore's SetMaxOpenConns(1) — fully serialises every
// transaction against this database, so whichever of Save/RevokeFamily
// commits first is authoritative for the other: a Save that commits first
// is guaranteed to be observed by a subsequent RevokeFamily's pointer read,
// and a Save that runs after RevokeFamily's tombstone commits is guaranteed
// to be rejected). If familyID is tombstoned, RowsAffected is 0 and
// ErrRefreshTokenFamilyRevoked is returned without writing anything.
func (s *sqliteRefreshTokenStore) Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("saving refresh token: %w", err)
	}
	res, err := tx.Exec(
		`INSERT OR REPLACE INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked)
		 SELECT ?, ?, ?, ?, ?, 0
		 WHERE ? = '' OR NOT EXISTS (SELECT 1 FROM revoked_families WHERE family_id = ?)`,
		tokenKey(refreshToken), accessToken, audience, familyID, expiresAt.Unix(), familyID, familyID,
	)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("saving refresh token: %w", err)
	}
	if n, _ := res.RowsAffected(); n == 0 {
		_ = tx.Rollback()
		return ErrRefreshTokenFamilyRevoked
	}
	if familyID != "" {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO family_current_access_token (family_id, access_token, expires_at) VALUES (?, ?, ?)`,
			familyID, accessToken, expiresAt.Unix(),
		); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("saving refresh token: updating family pointer: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("saving refresh token: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) Lookup(refreshToken string) (string, string, string, time.Time, bool) {
	var at, aud, fid string
	var expiresUnix int64
	err := s.db.QueryRow(
		`SELECT access_token, audience, family_id, expires_at FROM refresh_tokens
		 WHERE token_hash = ? AND expires_at > ? AND revoked = 0`,
		tokenKey(refreshToken), time.Now().Unix(),
	).Scan(&at, &aud, &fid, &expiresUnix)
	if err != nil {
		return "", "", "", time.Time{}, false
	}
	return at, aud, fid, time.Unix(expiresUnix, 0), true
}

func (s *sqliteRefreshTokenStore) LookupAny(refreshToken string) (string, string, string, time.Time, bool, bool) {
	var at, aud, fid string
	var expiresUnix int64
	var revokedInt int
	err := s.db.QueryRow(
		`SELECT access_token, audience, family_id, expires_at, revoked FROM refresh_tokens
		 WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(refreshToken), time.Now().Unix(),
	).Scan(&at, &aud, &fid, &expiresUnix, &revokedInt)
	if err != nil {
		return "", "", "", time.Time{}, false, false
	}
	return at, aud, fid, time.Unix(expiresUnix, 0), revokedInt != 0, true
}

func (s *sqliteRefreshTokenStore) Revoke(refreshToken string) error {
	_, err := s.db.Exec(
		`UPDATE refresh_tokens SET revoked = 1 WHERE token_hash = ? AND expires_at > ? AND revoked = 0`,
		tokenKey(refreshToken), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("revoking refresh token: %w", err)
	}
	return nil
}

// RevokeFamily marks every non-revoked row for familyID as revoked,
// tombstones familyID in revoked_families, and reads back the family's
// current access token pointer — all inside one transaction, so a concurrent
// Save for the same familyID (see Save's doc comment) either commits
// entirely before this transaction starts (in which case both the UPDATE
// below and the pointer read see it) or is blocked by the tombstone once
// this transaction commits (in which case it can never produce a pointer
// value this call could have missed). The single DB connection means there
// is no interleaving window between the two.
func (s *sqliteRefreshTokenStore) RevokeFamily(familyID string) (string, error) {
	if familyID == "" {
		return "", nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return "", fmt.Errorf("revoking refresh token family %q: %w", familyID, err)
	}
	if _, err := tx.Exec(
		`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ? AND revoked = 0`,
		familyID,
	); err != nil {
		_ = tx.Rollback()
		return "", fmt.Errorf("revoking refresh token family %q: %w", familyID, err)
	}
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO revoked_families (family_id, revoked_at) VALUES (?, ?)`,
		familyID, time.Now().Unix(),
	); err != nil {
		_ = tx.Rollback()
		return "", fmt.Errorf("tombstoning refresh token family %q: %w", familyID, err)
	}
	var currentAccessToken string
	err = tx.QueryRow(
		`SELECT access_token FROM family_current_access_token WHERE family_id = ? AND expires_at > ?`,
		familyID, time.Now().Unix(),
	).Scan(&currentAccessToken)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return "", fmt.Errorf("reading current access token for family %q: %w", familyID, err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("committing refresh token family revocation %q: %w", familyID, err)
	}
	return currentAccessToken, nil
}

func (s *sqliteRefreshTokenStore) SaveNonce(refreshToken, nonce string) error {
	_, err := s.db.Exec(
		`UPDATE refresh_tokens SET nonce = ? WHERE token_hash = ? AND expires_at > ?`,
		nonce, tokenKey(refreshToken), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving refresh token nonce: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) LookupNonce(refreshToken string) string {
	var nonce string
	_ = s.db.QueryRow(
		`SELECT nonce FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(refreshToken), time.Now().Unix(),
	).Scan(&nonce)
	return nonce
}

func (s *sqliteRefreshTokenStore) SaveProviderAccessToken(refreshToken, providerAccessToken string) error {
	_, err := s.db.Exec(
		`UPDATE refresh_tokens SET provider_access_token = ? WHERE token_hash = ? AND expires_at > ?`,
		providerAccessToken, tokenKey(refreshToken), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving refresh token provider access token: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) LookupProviderAccessToken(refreshToken string) string {
	var providerAccessToken string
	_ = s.db.QueryRow(
		`SELECT provider_access_token FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(refreshToken), time.Now().Unix(),
	).Scan(&providerAccessToken)
	return providerAccessToken
}

func (s *sqliteRefreshTokenStore) SaveProviderRefresh(refreshToken, providerRefreshToken string, providerAccessExpiry time.Time) error {
	_, err := s.db.Exec(
		`UPDATE refresh_tokens SET provider_refresh_token = ?, provider_access_expiry = ? WHERE token_hash = ? AND expires_at > ?`,
		providerRefreshToken, unixOrZero(providerAccessExpiry), tokenKey(refreshToken), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving refresh token provider refresh metadata: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) LookupProviderRefresh(refreshToken string) (string, time.Time) {
	var providerRefreshToken string
	var providerAccessExpiryUnix int64
	err := s.db.QueryRow(
		`SELECT provider_refresh_token, provider_access_expiry FROM refresh_tokens WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(refreshToken), time.Now().Unix(),
	).Scan(&providerRefreshToken, &providerAccessExpiryUnix)
	if err != nil || providerRefreshToken == "" {
		return "", time.Time{}
	}
	return providerRefreshToken, timeFromUnixOrZero(providerAccessExpiryUnix)
}

func (s *sqliteRefreshTokenStore) LookupFamilyByAccessToken(accessToken string) (string, string) {
	var familyID string
	err := s.db.QueryRow(
		`SELECT family_id FROM refresh_tokens
		 WHERE access_token = ? AND family_id != '' AND expires_at > ?
		 LIMIT 1`,
		accessToken, time.Now().Unix(),
	).Scan(&familyID)
	if err != nil {
		return "", ""
	}
	var currentAccessToken string
	_ = s.db.QueryRow(
		`SELECT access_token FROM family_current_access_token
		 WHERE family_id = ? AND expires_at > ?`,
		familyID, time.Now().Unix(),
	).Scan(&currentAccessToken)
	return familyID, currentAccessToken
}

func (s *sqliteRefreshTokenStore) UpdateProviderTokensByAccessToken(accessToken, providerAccessToken, providerRefreshToken string, providerAccessExpiry time.Time) error {
	_, err := s.db.Exec(
		`UPDATE refresh_tokens
		 SET provider_access_token = ?, provider_refresh_token = ?, provider_access_expiry = ?
		 WHERE revoked = 0 AND expires_at > ? AND (
			access_token = ? OR family_id IN (
				SELECT family_id FROM refresh_tokens
				WHERE access_token = ? AND family_id != '' AND expires_at > ?
			)
		 )`,
		providerAccessToken, providerRefreshToken, unixOrZero(providerAccessExpiry),
		time.Now().Unix(), accessToken, accessToken, time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("updating refresh token provider metadata by access token: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) Delete(refreshToken string) error {
	_, err := s.db.Exec(
		`DELETE FROM refresh_tokens WHERE token_hash = ?`,
		tokenKey(refreshToken),
	)
	if err != nil {
		return fmt.Errorf("deleting refresh token: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) RevokeJTI(jti string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO revoked_jti (jti, expires_at) VALUES (?, ?)`,
		jti, expiresAt.Unix(),
	)
	if err != nil {
		return fmt.Errorf("revoking jti: %w", err)
	}
	return nil
}

// IsJTIRevoked fails closed: sql.ErrNoRows (the jti is genuinely absent) is
// the only error treated as "not revoked". Any other error — a locked,
// unreadable, or corrupt database — is treated as revoked, because the
// alternative (failing open) would let an actually-revoked gateway JWT keep
// validating whenever the denylist happens to be unreadable.
func (s *sqliteRefreshTokenStore) IsJTIRevoked(jti string) bool {
	var expiresAt int64
	err := s.db.QueryRow(
		`SELECT expires_at FROM revoked_jti WHERE jti = ? AND expires_at > ?`,
		jti, time.Now().Unix(),
	).Scan(&expiresAt)
	if err == nil {
		return true
	}
	if errors.Is(err, sql.ErrNoRows) {
		return false
	}
	slog.Warn("jti denylist query failed; failing closed (treating token as revoked)", "err", err)
	return true
}

func (s *sqliteRefreshTokenStore) Sweep() error {
	_, err := s.sweepNow()
	if err != nil {
		return err
	}
	_, err = s.db.Exec(`DELETE FROM revoked_jti WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("sweeping expired revoked jti entries: %w", err)
	}
	_, err = s.db.Exec(`DELETE FROM family_current_access_token WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return fmt.Errorf("sweeping expired family access token pointers: %w", err)
	}
	return nil
}

func (s *sqliteRefreshTokenStore) sweepNow() (int64, error) {
	res, err := s.db.Exec(
		`DELETE FROM refresh_tokens WHERE expires_at <= ?`,
		time.Now().Unix(),
	)
	if err != nil {
		return 0, fmt.Errorf("sweeping expired refresh tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close releases the underlying database connection.
func (s *sqliteRefreshTokenStore) Close() error {
	return s.db.Close()
}

// ── SQLite TokenStore ────────────────────────────────────────────────────────

// sqliteTokenStore is the SQLite-backed primary TokenStore. Field updates are
// single UPDATE statements guarded by the expiry predicate, so the manual
// previous-value rollback pattern of fileTokenStore is unnecessary: a failed
// statement leaves the row untouched, and memory/disk can never diverge
// because the database is the only state.
type sqliteTokenStore struct {
	db *sql.DB
}

// encodeAudiences serialises audiences for the access_tokens.audiences column.
// An empty slice is stored as ” so decodeAudiences can round-trip it to nil.
func encodeAudiences(audiences []string) (string, error) {
	if len(audiences) == 0 {
		return "", nil
	}
	b, err := json.Marshal(audiences)
	if err != nil {
		return "", fmt.Errorf("encoding audiences: %w", err)
	}
	return string(b), nil
}

func decodeAudiences(s string) ([]string, error) {
	if s == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return nil, fmt.Errorf("decoding audiences: %w", err)
	}
	return out, nil
}

// unixOrZero maps time.Time's zero value to 0 rather than its (negative) Unix
// representation, so "no expiry hint" round-trips through the INTEGER column.
func unixOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.Unix()
}

func timeFromUnixOrZero(v int64) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}

// Save inserts or updates the row for token. Re-saving a non-expired token
// merges audiences and preserves every other field (subject only when the new
// subject is empty), matching the mem/file implementations; an expired row is
// treated as absent and fully reset. The read-merge-write runs inside one
// transaction, which the single DB connection serialises against all other
// store operations.
func (s *sqliteTokenStore) Save(token, subject string, audiences []string, expiresAt time.Time) error {
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("saving token: %w", err)
	}
	key := tokenKey(token)
	var (
		curSubject, curAudiences, curPAT, curPRT, curNonce, curJti string
		curPAE                                                     int64
		curRotationFailed                                          int
	)
	err = tx.QueryRow(
		`SELECT subject, audiences, provider_access_token, provider_refresh_token,
		        provider_access_expiry, rotation_failed, nonce, jti
		 FROM access_tokens WHERE token_hash = ? AND expires_at > ?`,
		key, time.Now().Unix(),
	).Scan(&curSubject, &curAudiences, &curPAT, &curPRT, &curPAE, &curRotationFailed, &curNonce, &curJti)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		_ = tx.Rollback()
		return fmt.Errorf("saving token: reading current entry: %w", err)
	}
	if subject != "" {
		curSubject = subject
	}
	existing, err := decodeAudiences(curAudiences)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("saving token: %w", err)
	}
	mergedAudiences, err := encodeAudiences(mergeAudiences(existing, audiences))
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("saving token: %w", err)
	}
	if _, err := tx.Exec(
		`INSERT OR REPLACE INTO access_tokens
		 (token_hash, subject, audiences, expires_at, provider_access_token,
		  provider_refresh_token, provider_access_expiry, rotation_failed, nonce, jti)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key, curSubject, mergedAudiences, expiresAt.Unix(),
		curPAT, curPRT, curPAE, curRotationFailed, curNonce, curJti,
	); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("saving token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("saving token: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) SaveProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) error {
	_, err := s.db.Exec(
		`UPDATE access_tokens SET provider_refresh_token = ?, provider_access_expiry = ?
		 WHERE token_hash = ? AND expires_at > ?`,
		providerRefreshToken, unixOrZero(providerAccessExpiry), tokenKey(token), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving token provider refresh metadata: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) SaveProviderAccessToken(token, providerAccessToken string) error {
	_, err := s.db.Exec(
		`UPDATE access_tokens SET provider_access_token = ? WHERE token_hash = ? AND expires_at > ?`,
		providerAccessToken, tokenKey(token), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving token provider access token: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) Lookup(token string) (TokenRecord, bool) {
	var (
		subject, audiencesEnc, pat, prt, nonce, jti string
		expiresUnix, paeUnix                        int64
		rotationFailedInt                           int
	)
	err := s.db.QueryRow(
		`SELECT subject, audiences, expires_at, provider_access_token, provider_refresh_token,
		        provider_access_expiry, rotation_failed, nonce, jti
		 FROM access_tokens WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(token), time.Now().Unix(),
	).Scan(&subject, &audiencesEnc, &expiresUnix, &pat, &prt, &paeUnix, &rotationFailedInt, &nonce, &jti)
	if err != nil {
		return TokenRecord{}, false
	}
	audiences, err := decodeAudiences(audiencesEnc)
	if err != nil {
		slog.Warn("token store entry has undecodable audiences; treating as miss", "err", err)
		return TokenRecord{}, false
	}
	return TokenRecord{
		Subject:                   subject,
		Audiences:                 audiences,
		ExpiresAt:                 time.Unix(expiresUnix, 0),
		ProviderAccessToken:       pat,
		ProviderRefreshToken:      prt,
		ProviderAccessExpiry:      timeFromUnixOrZero(paeUnix),
		RotationPermanentlyFailed: rotationFailedInt != 0,
		Nonce:                     nonce,
		Jti:                       jti,
	}, true
}

func (s *sqliteTokenStore) SaveNonce(token, nonce string) error {
	_, err := s.db.Exec(
		`UPDATE access_tokens SET nonce = ? WHERE token_hash = ? AND expires_at > ?`,
		nonce, tokenKey(token), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving token nonce: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) SaveJti(token, jti string) error {
	_, err := s.db.Exec(
		`UPDATE access_tokens SET jti = ? WHERE token_hash = ? AND expires_at > ?`,
		jti, tokenKey(token), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("saving token jti: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) MarkRotationFailed(token string) error {
	_, err := s.db.Exec(
		`UPDATE access_tokens SET rotation_failed = 1 WHERE token_hash = ? AND expires_at > ?`,
		tokenKey(token), time.Now().Unix(),
	)
	if err != nil {
		return fmt.Errorf("marking token rotation failed: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) Delete(token string) error {
	_, err := s.db.Exec(`DELETE FROM access_tokens WHERE token_hash = ?`, tokenKey(token))
	if err != nil {
		return fmt.Errorf("deleting token: %w", err)
	}
	return nil
}

func (s *sqliteTokenStore) Sweep() error {
	_, err := s.sweepNow()
	return err
}

func (s *sqliteTokenStore) sweepNow() (int64, error) {
	res, err := s.db.Exec(`DELETE FROM access_tokens WHERE expires_at <= ?`, time.Now().Unix())
	if err != nil {
		return 0, fmt.Errorf("sweeping expired tokens: %w", err)
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// Close releases the shared database connection. sql.DB.Close is idempotent,
// so closing both stores returned by NewSQLiteTokenStores is harmless.
func (s *sqliteTokenStore) Close() error {
	return s.db.Close()
}
