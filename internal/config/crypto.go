package config

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"strings"

	"filippo.io/age"
)

// encPrefix is the prefix for encrypted field values stored in config.yaml.
const encPrefix = "ENC[age:]"

// EncryptField encrypts plaintext using the key material's recipient and
// returns "ENC[age:]<base64-ciphertext>".
// The plaintext is never written to the log.
func EncryptField(km *KeyMaterial, plaintext string) (string, error) {
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, km.Encrypt)
	if err != nil {
		return "", fmt.Errorf("initializing age encryptor: %w", err)
	}
	if _, err := io.WriteString(w, plaintext); err != nil {
		_ = w.Close()
		return "", fmt.Errorf("writing to age encryptor: %w", err)
	}
	if err := w.Close(); err != nil {
		return "", fmt.Errorf("finalizing age encryption: %w", err)
	}
	return encPrefix + base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// DecryptField decrypts a "ENC[age:]<base64-ciphertext>" value and returns
// the plaintext. The plaintext and ciphertext are never written to the log.
func DecryptField(km *KeyMaterial, ciphertext string) (string, error) {
	if !strings.HasPrefix(ciphertext, encPrefix) {
		return "", fmt.Errorf("ciphertext does not start with %q", encPrefix)
	}
	b64 := ciphertext[len(encPrefix):]
	data, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("base64 decode: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(data), km.Decrypt)
	if err != nil {
		return "", fmt.Errorf("age decryption failed: %w", err)
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("reading decrypted data: %w", err)
	}
	return string(plaintext), nil
}

// IsEncrypted reports whether s is an ENC[age:] ciphertext value.
func IsEncrypted(s string) bool {
	return strings.HasPrefix(s, encPrefix)
}
