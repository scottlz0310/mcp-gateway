package githubapp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testPrivateKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return key, string(pemBytes)
}

func TestTokenSourceCachesAndRefreshesInstallationToken(t *testing.T) {
	_, privateKeyPEM := testPrivateKey(t)
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/app/installations/42/access_tokens" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-GitHub-Api-Version") != apiVersion {
			t.Fatalf("API version = %q", r.Header.Get("X-GitHub-Api-Version"))
		}
		assertJWTClaims(t, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), "12345", now)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token":      "ghs_token_" + string(rune('0'+call)),
			"expires_at": now.Add(time.Hour),
		})
	}))
	defer server.Close()

	source, err := NewTokenSource(Config{
		AppID:          12345,
		InstallationID: 42,
		PrivateKeyPEM:  privateKeyPEM,
		APIBaseURL:     server.URL,
		HTTPClient:     server.Client(),
		Now:            func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first != second || calls.Load() != 1 {
		t.Fatalf("cache miss: first=%q second=%q calls=%d", first, second, calls.Load())
	}

	refreshed, err := source.RefreshAfter401(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed == first || calls.Load() != 2 {
		t.Fatalf("forced refresh failed: token=%q calls=%d", refreshed, calls.Load())
	}
	status := source.Status()
	if !status.Ready || status.CredentialType != "github_app_installation" || status.InstallationID != 42 {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestTokenSourceRejectsInvalidConfiguration(t *testing.T) {
	_, privateKeyPEM := testPrivateKey(t)
	tests := []struct {
		name string
		cfg  Config
	}{
		{name: "missing app ID", cfg: Config{InstallationID: 1, PrivateKeyPEM: privateKeyPEM}},
		{name: "invalid installation ID", cfg: Config{AppID: 12345, PrivateKeyPEM: privateKeyPEM}},
		{name: "invalid private key", cfg: Config{AppID: 12345, InstallationID: 1, PrivateKeyPEM: "not-pem"}},
		{name: "invalid API URL", cfg: Config{AppID: 12345, InstallationID: 1, PrivateKeyPEM: privateKeyPEM, APIBaseURL: "file:///tmp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := NewTokenSource(tt.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestTokenSourceDoesNotExposeResponseBody(t *testing.T) {
	_, privateKeyPEM := testPrivateKey(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"token":"secret-response-token"}`))
	}))
	defer server.Close()
	source, err := NewTokenSource(Config{
		AppID: 12345, InstallationID: 1, PrivateKeyPEM: privateKeyPEM,
		APIBaseURL: server.URL, HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = source.Token(context.Background())
	if err == nil || strings.Contains(err.Error(), "secret-response-token") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func assertJWTClaims(t *testing.T, token, issuer string, now time.Time) {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT parts = %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		Issuer string `json:"iss"`
		Issued int64  `json:"iat"`
		Expiry int64  `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.Issuer != issuer || claims.Issued != now.Add(-time.Minute).Unix() || claims.Expiry != now.Add(9*time.Minute).Unix() {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}
