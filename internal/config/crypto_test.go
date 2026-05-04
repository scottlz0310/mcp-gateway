package config

import (
	"strings"
	"testing"
)

// testKeyMaterial returns a fresh random KeyMaterial for use in tests.
func testKeyMaterial(t *testing.T) *KeyMaterial {
	t.Helper()
	dir := t.TempDir()
	km, err := LoadKey(dir+"/gateway.key", nil)
	if err != nil {
		t.Fatalf("testKeyMaterial: %v", err)
	}
	return km
}

// TestEncryptDecryptRoundtrip verifies the full ENC[age:] encrypt/decrypt cycle.
func TestEncryptDecryptRoundtrip(t *testing.T) {
	km := testKeyMaterial(t)
	plaintext := "super-secret-value"

	enc, err := EncryptField(km, plaintext)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	if !IsEncrypted(enc) {
		t.Errorf("expected ENC prefix, got: %q", enc)
	}
	if strings.Contains(enc, plaintext) {
		t.Error("plaintext must not appear in ciphertext")
	}

	got, err := DecryptField(km, enc)
	if err != nil {
		t.Fatalf("DecryptField: %v", err)
	}
	if got != plaintext {
		t.Errorf("decrypted %q, want %q", got, plaintext)
	}
}

// TestDecryptField_WrongKey verifies that decrypting with a different key returns an error.
func TestDecryptField_WrongKey(t *testing.T) {
	km1 := testKeyMaterial(t)
	km2 := testKeyMaterial(t)

	enc, err := EncryptField(km1, "secret")
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	_, err = DecryptField(km2, enc)
	if err == nil {
		t.Fatal("expected decryption error with wrong key")
	}
}

// TestDecryptField_BadPrefix verifies that a value without ENC[age:] returns an error.
func TestDecryptField_BadPrefix(t *testing.T) {
	km := testKeyMaterial(t)
	_, err := DecryptField(km, "not-encrypted")
	if err == nil {
		t.Fatal("expected error for bad prefix")
	}
}

// TestIsEncrypted confirms correct detection.
func TestIsEncrypted(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"ENC[age:]abc123==", true},
		{"ENC[age:]", true},
		{"plaintext", false},
		{"", false},
		{"ENC[scrypt:]something", false},
	}
	for _, tc := range tests {
		if got := IsEncrypted(tc.s); got != tc.want {
			t.Errorf("IsEncrypted(%q) = %v, want %v", tc.s, got, tc.want)
		}
	}
}

// TestEncryptField_NoPlaintextInLogs verifies that the plaintext value
// does not appear in any log output during encryption.
func TestEncryptField_NoPlaintextInLogs(t *testing.T) {
	logBuf := captureLogs(t)
	km := testKeyMaterial(t)
	plaintext := "my-very-secret-value-xyz987"

	enc, err := EncryptField(km, plaintext)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	output := logBuf.String()
	if strings.Contains(output, plaintext) {
		t.Error("plaintext leaked to log")
	}
	// The full ENC[...] value must also not appear in logs.
	if strings.Contains(output, enc) {
		t.Error("ENC ciphertext leaked to log")
	}
}
