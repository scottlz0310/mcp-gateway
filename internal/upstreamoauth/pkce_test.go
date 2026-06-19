package upstreamoauth_test

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

func TestGenerateCodeVerifier_Uniqueness(t *testing.T) {
	v1, err := upstreamoauth.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() error: %v", err)
	}
	v2, err := upstreamoauth.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() error: %v", err)
	}
	if v1 == v2 {
		t.Error("expected different verifiers on each call")
	}
}

func TestGenerateCodeVerifier_Format(t *testing.T) {
	v, err := upstreamoauth.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() error: %v", err)
	}
	// base64url-encoded 32 bytes = 43 characters (no padding)
	if len(v) != 43 {
		t.Errorf("code_verifier length = %d, want 43", len(v))
	}
	// Must not contain padding characters
	if strings.Contains(v, "=") {
		t.Errorf("code_verifier must not contain '=' padding: %q", v)
	}
	// Must be valid base64url
	if _, err := base64.RawURLEncoding.DecodeString(v); err != nil {
		t.Errorf("code_verifier is not valid base64url: %v", err)
	}
}

func TestS256Challenge_Correctness(t *testing.T) {
	// RFC 7636 §B test vector
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	got := upstreamoauth.S256Challenge(verifier)

	h := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(h[:])

	if got != want {
		t.Errorf("S256Challenge(%q) = %q, want %q", verifier, got, want)
	}
}

func TestS256Challenge_NoPadding(t *testing.T) {
	verifier := "test-verifier-value"
	challenge := upstreamoauth.S256Challenge(verifier)
	if strings.Contains(challenge, "=") {
		t.Errorf("S256Challenge must not contain '=' padding: %q", challenge)
	}
}

func TestS256Challenge_RoundTrip(t *testing.T) {
	v, err := upstreamoauth.GenerateCodeVerifier()
	if err != nil {
		t.Fatalf("GenerateCodeVerifier() error: %v", err)
	}
	challenge := upstreamoauth.S256Challenge(v)

	// Verify manually
	h := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(h[:])
	if challenge != want {
		t.Errorf("S256Challenge round-trip mismatch: got %q, want %q", challenge, want)
	}
}
