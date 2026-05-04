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
			// handle. Fall back to a remove-then-rename, accepting the brief window
			// where the file is absent (safe during gateway startup).
			_ = os.Remove(path)
			if err2 := os.Rename(tmpPath, path); err2 != nil {
				return fmt.Errorf("atomically replacing %s: %w (Windows fallback also failed: %v)", path, err, err2)
			}
			ok = true
			return nil
		}
		return fmt.Errorf("atomically replacing %s: %w", path, err)
	}
	ok = true
	return nil
}
