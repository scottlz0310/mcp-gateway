package auth

import (
	"database/sql"
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
	revoked      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_rt_family  ON refresh_tokens (family_id) WHERE revoked = 0;
CREATE INDEX IF NOT EXISTS idx_rt_expires ON refresh_tokens (expires_at);
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

func (s *sqliteRefreshTokenStore) Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, 0)`,
		tokenKey(refreshToken), accessToken, audience, familyID, expiresAt.Unix(),
	)
	if err != nil {
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

func (s *sqliteRefreshTokenStore) RevokeFamily(familyID string) error {
	if familyID == "" {
		return nil
	}
	_, err := s.db.Exec(
		`UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ? AND revoked = 0`,
		familyID,
	)
	if err != nil {
		return fmt.Errorf("revoking refresh token family %q: %w", familyID, err)
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

func (s *sqliteRefreshTokenStore) Sweep() error {
	_, err := s.sweepNow()
	return err
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
