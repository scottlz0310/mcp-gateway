package config

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// writeFileAtomic writes data to path atomically using a temp-file + rename pattern.
// perm is applied to the temp file before rename on non-Windows systems (permissions
// are preserved through the rename on most POSIX filesystems).
// On Windows, chmod is not applied; callers should log a warning if needed.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return fmt.Errorf("creating temp file in %s: %w", dir, err)
	}
	tmpPath := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpPath)
		}
	}()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("closing temp file: %w", err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(tmpPath, perm); err != nil {
			return fmt.Errorf("setting permissions on %s: %w", path, err)
		}
	}
	if err := os.Rename(tmpPath, path); err != nil {
		if runtime.GOOS == "windows" {
			// On Windows, MoveFileEx can fail when the destination is open by another
			// handle. Use a backup-and-restore approach: rename the existing file to a
			// .bak first, rename the temp file to the target, then remove the .bak.
			// If the second rename also fails, restore the backup so no data is lost.
			bakPath := path + ".bak"
			if _, statErr := os.Stat(path); statErr == nil {
				if renErr := os.Rename(path, bakPath); renErr != nil {
					// Cannot create backup; return original rename error.
					return fmt.Errorf("atomically replacing %s: %w", path, err)
				}
				if err2 := os.Rename(tmpPath, path); err2 != nil {
					_ = os.Rename(bakPath, path) // restore backup on failure
					return fmt.Errorf("atomically replacing %s: %w (Windows fallback also failed: %v)", path, err, err2)
				}
				_ = os.Remove(bakPath)
			} else {
				// Target does not exist yet; simple rename suffices.
				if err2 := os.Rename(tmpPath, path); err2 != nil {
					return fmt.Errorf("atomically replacing %s: %w (Windows fallback also failed: %v)", path, err, err2)
				}
			}
			ok = true
			return nil
		}
		return fmt.Errorf("atomically replacing %s: %w", path, err)
	}
	ok = true
	return nil
}
