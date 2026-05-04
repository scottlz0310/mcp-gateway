package config

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"filippo.io/age"
	"golang.org/x/crypto/hkdf"
)

// KeyMaterial holds both the decryption identity and encryption recipient
// for use with EncryptField and DecryptField.
type KeyMaterial struct {
	Decrypt age.Identity  // X25519Identity — used by DecryptField (decryption only)
	Encrypt age.Recipient // X25519Recipient — used by EncryptField (encryption only)
}

// ErrKeyCorrupt indicates that the key file exists but cannot be used.
// The caller must NOT regenerate or overwrite the file.
var ErrKeyCorrupt = errors.New("gateway.key is corrupt or unreadable")

const (
	// minMasterKeyLen is the minimum byte length of MCP_GATEWAY_MASTER_KEY.
	minMasterKeyLen = 32

	// hkdfInfo is the HKDF context label for deterministic key derivation.
	hkdfInfo = "mcp-gateway-key-v1"
)

// LoadKey loads or generates the X25519 key material, following this priority:
//
//  1. keyPath file exists → parse and validate; corrupt file = ErrKeyCorrupt (never overwrite)
//  2. keyPath absent + masterKey non-empty (≥32 bytes) → deterministic HKDF derivation → save
//  3. keyPath absent + no masterKey → random generation → save
//
// A corrupt, empty, unreadable, or malformed key file always returns ErrKeyCorrupt.
// The caller should log the path/error and call os.Exit(1) — never regenerate the key.
func LoadKey(keyPath string, masterKey []byte) (*KeyMaterial, error) {
	_, err := os.Stat(keyPath)
	if err == nil {
		// File exists: load and validate. Any failure is fatal.
		return loadKeyFile(keyPath)
	}
	if !os.IsNotExist(err) {
		// Cannot stat — permission error, broken symlink, etc.
		return nil, fmt.Errorf("%w: cannot access %s: %v", ErrKeyCorrupt, keyPath, err)
	}

	// File does not exist — generate.
	var identity *age.X25519Identity
	if len(masterKey) > 0 {
		if len(masterKey) < minMasterKeyLen {
			return nil, fmt.Errorf("MCP_GATEWAY_MASTER_KEY must be at least %d bytes (got %d)", minMasterKeyLen, len(masterKey))
		}
		identity, err = deriveIdentityFromMasterKey(masterKey)
		if err != nil {
			return nil, fmt.Errorf("deriving X25519 identity from master key: %w", err)
		}
		slog.Info("derived X25519 identity from MCP_GATEWAY_MASTER_KEY", "key_path", keyPath)
	} else {
		identity, err = age.GenerateX25519Identity()
		if err != nil {
			return nil, fmt.Errorf("generating X25519 identity: %w", err)
		}
		slog.Info("generated new random X25519 identity", "key_path", keyPath)
	}

	if err := saveKeyFile(keyPath, identity); err != nil {
		return nil, fmt.Errorf("saving gateway key to %s: %w", keyPath, err)
	}
	// Re-read the file that was just written so the in-memory identity always
	// matches what is on disk. This also handles the unlikely but possible race
	// where two processes both observe gateway.key as absent, generate different
	// random identities, and one overwrites the other via atomic rename: after
	// both writes settle, both processes will load the same on-disk key.
	return loadKeyFile(keyPath)
}

// loadKeyFile reads, parses, and validates an existing key file.
// Any failure (empty, unreadable, invalid format) returns ErrKeyCorrupt.
// The key content is never written to the log.
func loadKeyFile(keyPath string) (*KeyMaterial, error) {
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrKeyCorrupt, keyPath, err)
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%w: file is empty: %s", ErrKeyCorrupt, keyPath)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "AGE-SECRET-KEY-") {
			identity, err := age.ParseX25519Identity(line)
			if err != nil {
				return nil, fmt.Errorf("%w: invalid key in %s: %v", ErrKeyCorrupt, keyPath, err)
			}
			// Best-effort tighten permissions on existing key files (e.g. operator-restored keys).
			if runtime.GOOS != "windows" {
				if chErr := os.Chmod(keyPath, 0600); chErr != nil {
					slog.Warn("could not set 0600 permissions on key file", "path", keyPath, "err", chErr)
				}
			}
			return identityToKeyMaterial(identity)
		}
	}
	return nil, fmt.Errorf("%w: no AGE-SECRET-KEY-1 line found in %s", ErrKeyCorrupt, keyPath)
}

// saveKeyFile writes the identity string to keyPath atomically with 0600 permissions.
// The key content is never written to the log.
func saveKeyFile(keyPath string, identity *age.X25519Identity) error {
	if err := writeFileAtomic(keyPath, []byte(identity.String()+"\n"), 0600); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		slog.Warn("running on Windows: cannot guarantee 0600 permissions on key file", "path", keyPath)
	}
	return nil
}

// identityToKeyMaterial converts an X25519Identity into a KeyMaterial.
func identityToKeyMaterial(identity *age.X25519Identity) (*KeyMaterial, error) {
	return &KeyMaterial{
		Decrypt: identity,
		Encrypt: identity.Recipient(),
	}, nil
}

// deriveIdentityFromMasterKey deterministically derives an X25519Identity
// using HKDF-SHA256 over masterKey, then encodes the 32-byte output as the
// age-standard "AGE-SECRET-KEY-1..." bech32 format before parsing.
// The same masterKey always yields the same identity.
func deriveIdentityFromMasterKey(masterKey []byte) (*age.X25519Identity, error) {
	h := hkdf.New(sha256.New, masterKey, nil, []byte(hkdfInfo))
	scalar := make([]byte, 32)
	if _, err := io.ReadFull(h, scalar); err != nil {
		return nil, fmt.Errorf("HKDF derivation failed: %w", err)
	}
	keyStr := encodeAGESecretKey(scalar)
	return age.ParseX25519Identity(keyStr)
}
