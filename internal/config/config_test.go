package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestLegacyAdapterYAMLRoundTrip(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "disabled", true: "enabled"}[enabled], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			cfg := &AppConfig{Gateway: GatewayConfig{LegacyAdapterEnabled: enabled}}
			if err := SaveConfig(path, cfg); err != nil {
				t.Fatal(err)
			}
			loaded, err := LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			if loaded.Gateway.LegacyAdapterEnabled != enabled {
				t.Fatal("YAML 設定が保持されません")
			}
		})
	}
}

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

	got, err := MigrateSecret(configPath, cfg2, km, "github")
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

	got, err := MigrateSecret(configPath, cfg, km, "github")
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

// TestMigrateSecret_FromEnvVar verifies that OAUTH_CLIENT_SECRET is
// encrypted and saved when the config field is absent.
func TestMigrateSecret_FromEnvVar(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	envSecret := "secret-from-env-var-xyz"
	t.Setenv("OAUTH_CLIENT_SECRET", envSecret)
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", "")
	resetLegacyEnvWarnedForTest()

	cfg := &AppConfig{} // no secret in config
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km, "github")
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

// TestMigrateSecret_FromLegacyEnvVar verifies that the deprecated
// GITHUB_MCP_CLIENT_SECRET env var still seeds the config when the new
// OAUTH_CLIENT_SECRET is unset, with a deprecation warning logged.
func TestMigrateSecret_FromLegacyEnvVar(t *testing.T) {
	logBuf := captureLogs(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	envSecret := "legacy-secret-abc"
	t.Setenv("OAUTH_CLIENT_SECRET", "")
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", envSecret)
	resetLegacyEnvWarnedForTest()

	cfg := &AppConfig{}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km, "github")
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}
	if got != envSecret {
		t.Errorf("got %q, want %q", got, envSecret)
	}
	out := logBuf.String()
	if !strings.Contains(out, "GITHUB_MCP_CLIENT_SECRET") {
		t.Errorf("expected deprecation warning mentioning GITHUB_MCP_CLIENT_SECRET, got: %s", out)
	}
	if !strings.Contains(out, "OAUTH_CLIENT_SECRET") {
		t.Errorf("expected deprecation warning to mention canonical OAUTH_CLIENT_SECRET, got: %s", out)
	}
}

// TestMigrateSecret_NewWinsOverLegacy verifies that when both env vars are
// set, OAUTH_CLIENT_SECRET wins and a warning is logged that the legacy is
// ignored.
func TestMigrateSecret_NewWinsOverLegacy(t *testing.T) {
	logBuf := captureLogs(t)
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	t.Setenv("OAUTH_CLIENT_SECRET", "new-secret-wins")
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", "old-secret-ignored")
	resetLegacyEnvWarnedForTest()

	cfg := &AppConfig{}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km, "github")
	if err != nil {
		t.Fatalf("MigrateSecret: %v", err)
	}
	if got != "new-secret-wins" {
		t.Errorf("expected OAUTH_CLIENT_SECRET to win, got %q", got)
	}
	out := logBuf.String()
	if !strings.Contains(out, "GITHUB_MCP_CLIENT_SECRET") || !strings.Contains(out, "ignored") {
		t.Errorf("expected warning that legacy var is ignored, got: %s", out)
	}
}

// TestMigrateSecret_NoSecretAnywhere verifies that an error is returned
// when neither config nor env var has the secret.
func TestMigrateSecret_NoSecretAnywhere(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	t.Setenv("OAUTH_CLIENT_SECRET", "")
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", "")

	cfg := &AppConfig{}
	_, err := MigrateSecret(configPath, cfg, km, "github")
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
	t.Setenv("OAUTH_CLIENT_SECRET", secretValue)
	t.Setenv("GITHUB_MCP_CLIENT_SECRET", "")
	resetLegacyEnvWarnedForTest()

	cfg := &AppConfig{}
	enc, err := MigrateSecret(configPath, cfg, km, "github")
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
	if err != nil || cfg == nil {
		t.Fatalf("expected non-nil AppConfig and nil error for missing file, got cfg=%v err=%v", cfg, err)
	}
	if cfg.Auth.GitHubClientSecret != "" {
		t.Errorf("expected empty secret, got: %q", cfg.Auth.GitHubClientSecret)
	}
}

func TestLoadConfig_TrustedProxies(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	data := []byte(`
gateway:
  trusted_proxies:
    - 127.0.0.1/32
    - 10.0.0.0/8
`)
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if len(cfg.Gateway.TrustedProxies) != 2 {
		t.Fatalf("trusted_proxies len: got %d, want 2", len(cfg.Gateway.TrustedProxies))
	}
	if cfg.Gateway.TrustedProxies[0] != "127.0.0.1/32" || cfg.Gateway.TrustedProxies[1] != "10.0.0.0/8" {
		t.Errorf("trusted_proxies: got %#v", cfg.Gateway.TrustedProxies)
	}
}

// TestMigrateSecret_GenericOIDC verifies that when provider is "oidc",
// client_secret is used and migrated instead of github_client_secret.
func TestMigrateSecret_GenericOIDC(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	km := testKeyMaterial(t)
	plaintext := "my-generic-oidc-client-secret"

	cfg := &AppConfig{Auth: AuthConfig{ClientSecret: plaintext}}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	got, err := MigrateSecret(configPath, cfg, km, "oidc")
	if err != nil {
		t.Fatalf("MigrateSecret (oidc): %v", err)
	}
	if got != plaintext {
		t.Errorf("got %q, want %q", got, plaintext)
	}

	// Config file should now hold an encrypted value for client_secret.
	reloaded, _ := LoadConfig(configPath)
	if !IsEncrypted(reloaded.Auth.ClientSecret) {
		t.Error("config file should have been rewritten with encrypted value")
	}
	if strings.Contains(reloaded.Auth.ClientSecret, plaintext) {
		t.Error("plaintext must not remain in config file after migration")
	}
}

// TestMigrateOIDCPrivateKey verifies that OIDCPrivateKey is generated, encrypted,
// saved to config, and decrypted correctly on subsequent loads.
func TestMigrateOIDCPrivateKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	km := testKeyMaterial(t)

	cfg := &AppConfig{}
	if err := SaveConfig(configPath, cfg); err != nil {
		t.Fatalf("SaveConfig: %v", err)
	}

	// 1. Initial generation
	privKey1, err := MigrateOIDCPrivateKey(configPath, cfg, km)
	if err != nil {
		t.Fatalf("MigrateOIDCPrivateKey (generate): %v", err)
	}
	if privKey1 == nil {
		t.Errorf("expected non-nil private key")
		return
	}

	// Config should now hold the encrypted value
	reloaded, err := LoadConfig(configPath)
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if !IsEncrypted(reloaded.Auth.OIDCPrivateKey) {
		t.Error("config should hold encrypted OIDC private key")
	}

	// 2. Load existing key from config
	privKey2, err := MigrateOIDCPrivateKey(configPath, reloaded, km)
	if err != nil {
		t.Fatalf("MigrateOIDCPrivateKey (load): %v", err)
	}
	if privKey2 == nil {
		t.Errorf("expected non-nil loaded private key")
		return
	}

	// Keys should be identical (same N and D for RSA key)
	if privKey1.N.Cmp(privKey2.N) != 0 || privKey1.D.Cmp(privKey2.D) != 0 {
		t.Error("expected loaded private key to match generated private key")
	}
}

// TestRouteConfig_UpstreamOAuthNullAndBlankDecodedAsNil documents that yaml.v3
// decodes both `null` and a blank value (key present with no value) to nil for
// *string fields. nil is indistinguishable from a missing field — ParseFromConfig
// treats it as "absent" (upstream OAuth disabled), with no validation error.
// Only an explicit quoted empty string (`upstream_oauth: ""`) yields ptr("") and
// is rejected as a fail-closed violation.
func TestRouteConfig_UpstreamOAuthNullAndBlankDecodedAsNil(t *testing.T) {
	cases := []struct {
		name       string
		input      string
		checkOAuth bool
		checkScope bool
	}{
		{"oauth_null", "name: r\nprefix: /mcp\nupstream: https://up.example.com/mcp\nupstream_oauth: null\n", true, false},
		{"oauth_blank", "name: r\nprefix: /mcp\nupstream: https://up.example.com/mcp\nupstream_oauth:\n", true, false},
		{"scope_null", "name: r\nprefix: /mcp\nupstream: https://up.example.com/mcp\nupstream_oauth_scope: null\n", false, true},
		{"scope_blank", "name: r\nprefix: /mcp\nupstream: https://up.example.com/mcp\nupstream_oauth_scope:\n", false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var r RouteConfig
			if err := yaml.Unmarshal([]byte(tc.input), &r); err != nil {
				t.Fatalf("yaml.Unmarshal: %v", err)
			}
			if tc.checkOAuth && r.UpstreamOAuth != nil {
				t.Errorf("UpstreamOAuth: expected nil (blank/null decodes to nil), got ptr(%q)", *r.UpstreamOAuth)
			}
			if tc.checkScope && r.UpstreamOAuthScope != nil {
				t.Errorf("UpstreamOAuthScope: expected nil (blank/null decodes to nil), got ptr(%q)", *r.UpstreamOAuthScope)
			}
		})
	}
}

func TestMigrateGitHubAppPrivateKey(t *testing.T) {
	tests := []struct {
		name      string
		configKey string
		envKey    string
		want      string
		wantErr   bool
	}{
		{name: "plaintext config", configKey: "private-key-from-config", want: "private-key-from-config"},
		{name: "environment", envKey: "private-key-from-env", want: "private-key-from-env"},
		{name: "missing", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("GITHUB_APP_PRIVATE_KEY", tt.envKey)
			configPath := filepath.Join(t.TempDir(), "config.yaml")
			cfg := &AppConfig{GitHubApp: GitHubAppConfig{PrivateKey: tt.configKey}}
			km := testKeyMaterial(t)
			got, err := MigrateGitHubAppPrivateKey(configPath, cfg, km)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != tt.want {
				t.Fatalf("private key = %q, want %q", got, tt.want)
			}
			reloaded, err := LoadConfig(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !IsEncrypted(reloaded.GitHubApp.PrivateKey) || strings.Contains(reloaded.GitHubApp.PrivateKey, tt.want) {
				t.Fatal("GitHub App private key was not encrypted at rest")
			}
		})
	}
}

func TestMigrateGitHubAppPrivateKeyEncryptedRoundTrip(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	km := testKeyMaterial(t)
	encrypted, err := EncryptField(km, "private-key")
	if err != nil {
		t.Fatal(err)
	}
	cfg := &AppConfig{GitHubApp: GitHubAppConfig{PrivateKey: encrypted}}
	got, err := MigrateGitHubAppPrivateKey(configPath, cfg, km)
	if err != nil {
		t.Fatal(err)
	}
	if got != "private-key" {
		t.Fatalf("private key = %q", got)
	}
}

func TestMigrateGitHubAppPrivateKeyFromPath(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "app.pem")
	if err := os.WriteFile(keyPath, []byte("private-key-from-file"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GITHUB_APP_PRIVATE_KEY", "")
	t.Setenv("GITHUB_APP_PRIVATE_KEY_PATH", keyPath)
	cfg := &AppConfig{}
	got, err := MigrateGitHubAppPrivateKey(filepath.Join(dir, "config.yaml"), cfg, testKeyMaterial(t))
	if err != nil {
		t.Fatal(err)
	}
	if got != "private-key-from-file" || !IsEncrypted(cfg.GitHubApp.PrivateKey) {
		t.Fatalf("unexpected migration result")
	}
}
