package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestMigrateSecret_EncryptedValue decrypts an ENC[age:] value from config.
func TestMigrateSecret_EncryptedValue(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	plaintext := "my-github-client-secret"

	enc, err := EncryptField(km, plaintext)
	if err != nil {
		t.Fatalf("EncryptField: %v", err)
	}

	cfg := &AppConfig{Auth: AuthConfig{GitHubClientSecret: enc}}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	cfg2, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg2, km)
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}
	if got != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}

	// Config file should still have the ENC[...] value (no double-encryption).
	reloaded, _ := LoadConfig(configPath)
	if !IsEncrypted(reloaded.Auth.GitHubClientSecret) {
		t.Error("config should still hold the encrypted value")
	}
}

// TestMigrateSecret_PlaintextRewritten verifies that a plaintext secret is
// encrypted and written back to the config file.
func TestMigrateSecret_PlaintextRewritten(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	plaintext := "plain-secret-in-config"

	cfg := &AppConfig{Auth: AuthConfig{GitHubClientSecret: plaintext}}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km)
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}
	if got != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}

	// Config file should now hold an encrypted value.
	reloaded, _ := LoadConfig(configPath)
	if !IsEncrypted(reloaded.Auth.GitHubClientSecret) {
		t.Error("config file should have been rewritten with encrypted value")
	}
	if strings.Contains(reloaded.Auth.GitHubClientSecret, plaintext) {
		t.Error("plaintext must not remain in config file after migration")
	}
}

// TestMigrateSecret_FromEnvVar verifies that GITHUB_MCP_CLIENT_SECRET is
// encrypted and saved when the config field is absent.
func TestMigrateSecret_FromEnvVar(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	envSecret := "secret-from-env-var-xyz"
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", envSecret)

	cfg := &AppConfig{} // no secret in config
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km)
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}
	if got != envSecret {
		t.Errorf("got %q, want %q", got, envSecret)
	}

	// Config file should now hold an encrypted value.
	reloaded, _ := LoadConfig(configPath)
	if !IsEncrypted(reloaded.Auth.GitHubClientSecret) {
		t.Error("config file should have been written with encrypted value from env")
	}
}

// TestMigrateSecret_NoSecretAnywhere verifies that an error is returned
// when neither config nor env var has the secret.
func TestMigrateSecret_NoSecretAnywhere(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	os.Unsetenv("GITHUB_MCP_CLIENT_SECRET")

	cfg := &AppConfig{}
	_, err := MigrateSecret(configPath, cfg, km)
	if err == nil {
		t.Fatal("expected error when no secret is available")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("error should indicate requirement, got: %v", err)
	}
}

// TestMigrateSecret_NoSecretInLogs verifies that secrets don't leak to logs.
func TestMigrateSecret_NoSecretInLogs(t *testing.T) {
	logBuf := captureLogs(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	secretValue := "ultrasecret-do-not-log-me-abc123"
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", secretValue)

	cfg := &AppConfig{}
	enc, err := MigrateSecret(configPath, cfg, km)
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}

	// Also exercise the LoadConfig path (restart scenario) while still capturing logs.
	if _, err := LoadConfig(configPath); err != nil {
		t.Fatalf("LoadConfig with encrypted config: %v", err)
	}

	output := logBuf.String()
	if strings.Contains(output, secretValue) {
		t.Error("plaintext secret leaked to log output")
	}
	if strings.Contains(output, enc) {
		t.Error("full ENC[age:...] ciphertext leaked to log output")
	}
	// Catch any partial logging of the encrypted prefix from either path.
	if strings.Contains(output, "ENC[age:]") {
		t.Error("ENC[age:] prefix leaked to log output")
	}
}

// TestLoadConfig_MissingFile verifies that a missing config returns empty AppConfig.
func TestLoadConfig_MissingFile(t *testing.T) {
	cfg, err := LoadConfig("/nonexistent/path/config.yaml")
	if err != nil {
		t.Fatalf("expected nil error for missing file, got: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil AppConfig")
	}
	if cfg.Auth.GitHubClientSecret != "" {
		t.Errorf("expected empty secret, got: %q", cfg.Auth.GitHubClientSecret)
	}
}
