package auth

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// migrateFileRefreshTokenStore reads an existing tokens.json.refresh file,
// inserts all valid entries into dst, then renames the file to
// <path>.migrated so it is not re-processed on the next startup.
//
// If the source file does not exist the function returns nil (no-op).
// If any step fails the source file is left untouched so the operator can
// inspect the data; the error is returned and the caller should abort.
func migrateFileRefreshTokenStore(path string, dst RefreshTokenStore) error {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading legacy refresh token store %q: %w", path, err)
	}
	if len(data) == 0 {
		_ = os.Rename(path, path+".migrated")
		return nil
	}

	var entries map[string]fileRTEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing legacy refresh token store %q: %w", path, err)
	}

	imported := 0
	for hash, e := range entries {
		// token_hash is already hashed; insert directly via the raw SQL path.
		// We use the SQLite store's db field via a type assertion so we can
		// insert pre-hashed keys without going through tokenKey() again.
		sq, ok := dst.(*sqliteRefreshTokenStore)
		if !ok {
			return fmt.Errorf("migration destination is not a SQLite store")
		}
		revokedInt := 0
		if e.Revoked {
			revokedInt = 1
		}
		_, err := sq.db.Exec(
			`INSERT OR IGNORE INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			hash, e.AccessToken, e.Audience, e.FamilyID, e.ExpiresAt.Unix(), revokedInt,
		)
		if err != nil {
			return fmt.Errorf("migrating refresh token entry: %w", err)
		}
		imported++
	}

	migratedPath := path + ".migrated"
	if err := os.Rename(path, migratedPath); err != nil {
		return fmt.Errorf("renaming legacy refresh token store after migration: %w", err)
	}
	slog.Info("legacy refresh token store migrated to SQLite",
		"source", path, "renamed_to", migratedPath, "imported", imported)
	return nil
}
