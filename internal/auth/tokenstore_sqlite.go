package auth

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteRTSchema = `
CREATE TABLE IF NOT EXISTS refresh_tokens (
	token_hash   TEXT    PRIMARY KEY,
	access_token TEXT    NOT NULL,
	audience     TEXT    NOT NULL DEFAULT '',
	family_id    TEXT    NOT NULL DEFAULT '',
	expires_at   INTEGER NOT NULL,
	revoked      INTEGER NOT NULL DEFAULT 0,
	nonce        TEXT    NOT NULL DEFAULT '',
	provider_access_token TEXT NOT NULL DEFAULT ''
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

// NewSQLiteRefreshTokenStore returns a SQLite-backed RefreshTokenStore.
// path may be ":memory:" for in-process testing.
func NewSQLiteRefreshTokenStore(path string) (RefreshTokenStore, error) {
	// WAL mode for concurrent readers; busy_timeout avoids immediate SQLITE_BUSY.
	dsn := path + "?_journal_mode=WAL&_busy_timeout=5000&_foreign_keys=on"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("opening SQLite refresh token store %q: %w", path, err)
	}
	db.SetMaxOpenConns(1) // SQLite WAL allows 1 writer; serialise via the connection pool
	if _, err := db.Exec(sqliteRTSchema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("initialising SQLite refresh token store schema: %w", err)
	}
	// Add nonce/provider_access_token columns to existing databases created before
	// these fields were introduced. ALTER TABLE ADD COLUMN is idempotent in SQLite
	// when the column already exists (returns "duplicate column name" which we
	// intentionally ignore).
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN nonce TEXT NOT NULL DEFAULT ''`)
	_, _ = db.Exec(`ALTER TABLE refresh_tokens ADD COLUMN provider_access_token TEXT NOT NULL DEFAULT ''`)
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
			slog.Warn("SQLite refresh token store chmod failed", "path", path, "err", err)
		}
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
