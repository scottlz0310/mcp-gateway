package config

import (
	"bytes"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"filippo.io/age"
)

// captureLogs redirects slog to a buffer and returns a cleanup function.
// Call cleanup() (or use defer) to restore the original logger.
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// writeKeyFile writes a valid age secret key to a temp file and returns the path.
func writeKeyFile(t *testing.T, dir string, identity *age.X25519Identity) string {
	t.Helper()
	path := filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(path, []byte(identity.String()+"\n"), 0600); err != nil {
		t.Fatalf("writeKeyFile: %v", err)
	}
	return path
}

// TestLoadKey_ExistingFileWins verifies that an existing gateway.key takes
// precedence over MCP_GATEWAY_MASTER_KEY.
func TestLoadKey_ExistingFileWins(t *testing.T) {
	dir := t.TempDir()

	// Create a known identity and write it to disk.
	original, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	keyPath := writeKeyFile(t, dir, original)

	// Provide a master key — should be ignored.
	masterKey := bytes.Repeat([]byte("k"), 32)
	km, err := LoadKey(keyPath, masterKey)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	// The loaded key must match the original (compare recipient public key via String).
	loaded, ok := km.Decrypt.(*age.X25519Identity)
	if !ok {
		t.Fatal("Decrypt is not *X25519Identity")
	}
	if loaded.Recipient().String() != original.Recipient().String() {
		t.Errorf("key mismatch: got %s, want %s", loaded.Recipient(), original.Recipient())
	}
}

// TestLoadKey_DeterministicFromMasterKey verifies that the same master key
// always produces the same identity, and a different key produces a different one.
func TestLoadKey_DeterministicFromMasterKey(t *testing.T) {
	masterKey := []byte("a-sufficiently-long-master-key-1234")

	// First derivation.
	dir1 := t.TempDir()
	km1, err := LoadKey(filepath.Join(dir1, "gateway.key"), masterKey)
	if err != nil {
		t.Fatalf("first LoadKey: %v", err)
	}

	// Second derivation with the same key (different temp dir, no existing file).
	dir2 := t.TempDir()
	km2, err := LoadKey(filepath.Join(dir2, "gateway.key"), masterKey)
	if err != nil {
		t.Fatalf("second LoadKey: %v", err)
	}

	id1 := km1.Decrypt.(*age.X25519Identity)
	id2 := km2.Decrypt.(*age.X25519Identity)
	if id1.Recipient().String() != id2.Recipient().String() {
		t.Error("same master key must produce the same identity")
	}

	// Different master key must produce a different identity.
	dir3 := t.TempDir()
	otherKey := []byte("a-different-master-key-for-testing!")
	km3, err := LoadKey(filepath.Join(dir3, "gateway.key"), otherKey)
	if err != nil {
		t.Fatalf("third LoadKey: %v", err)
	}
	id3 := km3.Decrypt.(*age.X25519Identity)
	if id1.Recipient().String() == id3.Recipient().String() {
		t.Error("different master keys must produce different identities")
	}
}

// TestLoadKey_RandomGenerationNoMasterKey verifies that without a master key
// a random identity is generated and saved.
func TestLoadKey_RandomGenerationNoMasterKey(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "gateway.key")

	km, err := LoadKey(keyPath, nil)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	if km.Decrypt == nil || km.Encrypt == nil {
		t.Fatal("KeyMaterial fields must not be nil")
	}

	// The file must have been created.
	if _, err := os.Stat(keyPath); err != nil {
		t.Errorf("key file not created: %v", err)
	}

	// Re-loading must return the same key.
	km2, err := LoadKey(keyPath, nil)
	if err != nil {
		t.Fatalf("second LoadKey: %v", err)
	}
	id1 := km.Decrypt.(*age.X25519Identity).Recipient().String()
	id2 := km2.Decrypt.(*age.X25519Identity).Recipient().String()
	if id1 != id2 {
		t.Error("re-loading key file must return the same identity")
	}
}

// TestLoadKey_CorruptFile_Empty verifies that an empty key file returns
// ErrKeyCorrupt and does not overwrite the file.
func TestLoadKey_CorruptFile_Empty(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(keyPath, []byte(""), 0600); err != nil {
		t.Fatalf("write empty file: %v", err)
	}

	_, err := LoadKey(keyPath, nil)
	if !errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("expected ErrKeyCorrupt, got: %v", err)
	}

	// File must still be the empty file (not overwritten).
	data, _ := os.ReadFile(keyPath)
	if len(data) != 0 {
		t.Errorf("corrupt file must not be overwritten; got %d bytes", len(data))
	}
}

// TestLoadKey_CorruptFile_InvalidFormat verifies that a file with content
// but no AGE-SECRET-KEY-1 line returns ErrKeyCorrupt.
func TestLoadKey_CorruptFile_InvalidFormat(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "gateway.key")
	if err := os.WriteFile(keyPath, []byte("not-a-valid-key\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadKey(keyPath, nil)
	if !errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("expected ErrKeyCorrupt, got: %v", err)
	}
}

// TestLoadKey_CorruptFile_BadKeyLine verifies that a file with an
// AGE-SECRET-KEY- prefix but invalid bech32 returns ErrKeyCorrupt.
func TestLoadKey_CorruptFile_BadKeyLine(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "gateway.key")
	// Looks like a key line but is truncated/mangled.
	if err := os.WriteFile(keyPath, []byte("AGE-SECRET-KEY-INVALID\n"), 0600); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := LoadKey(keyPath, nil)
	if !errors.Is(err, ErrKeyCorrupt) {
		t.Errorf("expected ErrKeyCorrupt, got: %v", err)
	}
}

// TestLoadKey_MasterKeyTooShort verifies that a master key shorter than
// minMasterKeyLen bytes returns an error.
func TestLoadKey_MasterKeyTooShort(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "gateway.key")

	_, err := LoadKey(keyPath, []byte("tooshort"))
	if err == nil {
		t.Fatal("expected error for short master key")
	}
	if !strings.Contains(err.Error(), "at least") {
		t.Errorf("error should mention minimum length, got: %v", err)
	}
}

// TestLoadKey_NoSecretInLogs verifies that the key content never appears
// in log output.
func TestLoadKey_NoSecretInLogs(t *testing.T) {
	logBuf := captureLogs(t)
	dir := t.TempDir()
	masterKey := []byte("this-is-a-known-master-key-for-test!")

	_, err := LoadKey(filepath.Join(dir, "gateway.key"), masterKey)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}

	output := logBuf.String()
	// The master key raw value must not appear in log output.
	if strings.Contains(output, "this-is-a-known-master-key-for-test!") {
		t.Error("master key leaked to log output")
	}
	// AGE-SECRET-KEY- content must not appear in log output.
	if strings.Contains(output, "AGE-SECRET-KEY-") {
		t.Error("key content leaked to log output")
	}
}
