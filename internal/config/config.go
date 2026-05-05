package config

import (
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// RouteConfig holds a single proxy route that can be persisted in config.yaml.
type RouteConfig struct {
	Name     string `yaml:"name"             json:"name"`
	Prefix   string `yaml:"prefix"           json:"prefix"`
	Upstream string `yaml:"upstream"         json:"upstream"`
	NoAuth   bool   `yaml:"no_auth,omitempty" json:"no_auth,omitempty"`
}

// SetupConfig holds first-run wizard state.
type SetupConfig struct {
	Completed bool `yaml:"completed,omitempty"`
}

// AppConfig is the application configuration stored in config.yaml.
type AppConfig struct {
	Auth    AuthConfig    `yaml:"auth,omitempty"`
	Gateway GatewayConfig `yaml:"gateway,omitempty"`
	Routes  []RouteConfig `yaml:"routes,omitempty"`
	Setup   SetupConfig   `yaml:"setup,omitempty"`
}

// AuthConfig holds OAuth client credentials.
type AuthConfig struct {
	GitHubClientID     string `yaml:"github_client_id,omitempty"`
	GitHubClientSecret string `yaml:"github_client_secret,omitempty"`
}

// GatewayConfig holds gateway-level settings that can be persisted in config.yaml.
type GatewayConfig struct {
	BaseURL     string `yaml:"base_url,omitempty"`
	Port        string `yaml:"port,omitempty"`
	OAuthScopes string `yaml:"oauth_scopes,omitempty"`
}

// LoadConfig reads AppConfig from path.
// If the file does not exist, an empty AppConfig is returned (not an error).
func LoadConfig(path string) (*AppConfig, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &AppConfig{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("reading config file %q: %w", path, err)
	}
	var cfg AppConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config file %q: %w", path, err)
	}
	return &cfg, nil
}

// SaveConfig writes cfg to path with 0600 permissions using an atomic temp-file+rename.
//
// Note: because AppConfig is a narrow struct, any YAML fields not defined in AppConfig
// (unknown keys, user-added comments) will be lost on rewrite. SaveConfig is called
// during secret migration and by the setup wizard. Manual edits to config.yaml should
// be made after the initial setup run.
func SaveConfig(path string, cfg *AppConfig) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshaling config: %w", err)
	}
	if err := writeFileAtomic(path, data, 0600); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		slog.Warn("running on Windows: cannot guarantee 0600 permissions on config file", "path", path)
	}
	return nil
}

// MigrateSecret resolves the GitHub OAuth client secret, following this priority:
//
//  1. cfg.Auth.GitHubClientSecret is "ENC[age:]..." → decrypt and return plaintext
//  2. cfg.Auth.GitHubClientSecret is non-empty plaintext → encrypt, write back, return plaintext
//  3. field empty/absent + GITHUB_MCP_CLIENT_SECRET env var set → encrypt, save to config, return
//  4. field empty + env var absent → return error
//
// The config file at configPath is updated in cases 2 and 3.
// The returned plaintext is never written to the log.
func MigrateSecret(configPath string, cfg *AppConfig, km *KeyMaterial) (string, error) {
	secret := cfg.Auth.GitHubClientSecret

	switch {
	case IsEncrypted(secret):
		plaintext, err := DecryptField(km, secret)
		if err != nil {
			return "", fmt.Errorf("decrypting github_client_secret: %w", err)
		}
		return plaintext, nil

	case strings.TrimSpace(secret) != "":
		slog.Info("plaintext github_client_secret found in config; encrypting and rewriting")
		encrypted, err := EncryptField(km, secret)
		if err != nil {
			return "", fmt.Errorf("encrypting github_client_secret from config: %w", err)
		}
		cfg.Auth.GitHubClientSecret = encrypted
		if err := SaveConfig(configPath, cfg); err != nil {
			return "", fmt.Errorf("saving config after encrypting github_client_secret: %w", err)
		}
		return secret, nil

	default:
		envSecret, ok := os.LookupEnv("GITHUB_MCP_CLIENT_SECRET")
		if ok && strings.TrimSpace(envSecret) != "" {
			envSecret = strings.TrimSpace(envSecret)
			slog.Info("encrypting GITHUB_MCP_CLIENT_SECRET from env and saving to config")
			encrypted, err := EncryptField(km, envSecret)
			if err != nil {
				return "", fmt.Errorf("encrypting GITHUB_MCP_CLIENT_SECRET from env: %w", err)
			}
			cfg.Auth.GitHubClientSecret = encrypted
			if err := SaveConfig(configPath, cfg); err != nil {
				return "", fmt.Errorf("saving config after encrypting GITHUB_MCP_CLIENT_SECRET: %w", err)
			}
			return envSecret, nil
		}
		return "", fmt.Errorf("github_client_secret is required: set GITHUB_MCP_CLIENT_SECRET env var or provide an encrypted value in config.yaml")
	}
}
