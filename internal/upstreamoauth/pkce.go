package upstreamoauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// GenerateCodeVerifier returns a cryptographically random PKCE code_verifier
// using 32 bytes of entropy, base64url-encoded without padding (RFC 7636 §4.1).
func GenerateCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// S256Challenge computes the PKCE code_challenge from verifier using the S256
// method: BASE64URL(SHA256(ASCII(verifier))) without padding (RFC 7636 §4.2).
func S256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
