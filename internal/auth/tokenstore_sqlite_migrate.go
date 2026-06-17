package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
)

// migrateFileRefreshTokenStore reads an existing tokens.json.refresh file,
// inserts all valid entries into dst inside a single transaction, then renames
// the file to <path>.migrated so it is not re-processed on the next startup.
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
		_ = renameOverwrite(path, path+".migrated")
		return nil
	}

	var entries map[string]fileRTEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("parsing legacy refresh token store %q: %w", path, err)
	}

	sq, ok := dst.(*sqliteRefreshTokenStore)
	if !ok {
		return fmt.Errorf("migration destination is not a SQLite store")
	}

	// Wrap all inserts in a single transaction: atomic and significantly faster
	// than one fsync per row when the entry count is large.
	tx, err := sq.db.BeginTx(context.Background(), nil)
	if err != nil {
		return fmt.Errorf("beginning migration transaction: %w", err)
	}
	stmt, err := tx.Prepare(
		`INSERT OR IGNORE INTO refresh_tokens (token_hash, access_token, audience, family_id, expires_at, revoked)
		 VALUES (?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("preparing migration insert: %w", err)
	}
	defer stmt.Close()

	imported := 0
	for hash, e := range entries {
		revokedInt := 0
		if e.Revoked {
			revokedInt = 1
		}
		if _, err := stmt.Exec(hash, e.AccessToken, e.Audience, e.FamilyID, e.ExpiresAt.Unix(), revokedInt); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("migrating refresh token entry: %w", err)
		}
		imported++
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing migration transaction: %w", err)
	}

	migratedPath := path + ".migrated"
	if err := renameOverwrite(path, migratedPath); err != nil {
		return fmt.Errorf("renaming legacy refresh token store after migration: %w", err)
	}
	slog.Info("legacy refresh token store migrated to SQLite",
		"source", path, "renamed_to", migratedPath, "imported", imported)
	return nil
}

// renameOverwrite renames src to dst, removing dst first if it exists.
// This avoids os.Rename failures on Windows when dst already exists.
func renameOverwrite(src, dst string) error {
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing existing %q: %w", dst, err)
	}
	return os.Rename(src, dst)
}
