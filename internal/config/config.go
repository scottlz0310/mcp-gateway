package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
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
	// UpstreamBearerTokenEnv names the env var whose value is injected as the
	// upstream Authorization Bearer token. When empty, the client OAuth token is used.
	UpstreamBearerTokenEnv string `yaml:"upstream_bearer_token_env,omitempty" json:"upstream_bearer_token_env,omitempty"`
	// RequiredAudience is the aud claim value required in access tokens for this
	// route (e.g. "mcp-server", "external-mcp"). Defaults to "mcp-gateway" when
	// empty. Clients obtain a token with this audience by passing resource=<route-name>
	// to the /token endpoint.
	RequiredAudience string `yaml:"required_audience,omitempty" json:"required_audience,omitempty"`
	// UpstreamOAuth enables upstream OAuth delegation. Value is "auto" or an
	// absolute issuer URL (http/https). Discovery and token exchange are handled by
	// subsequent issues; this field is parsed and validated only at startup.
	// Use *string so that an explicit empty value ("") is distinguishable from
	// the field being absent (nil), enabling fail-closed validation for empty strings.
	UpstreamOAuth *string `yaml:"upstream_oauth,omitempty"       json:"upstream_oauth,omitempty"`
	// UpstreamOAuthScope is the space-separated OAuth scope string requested from
	// the upstream authorization server. Comma-separated values are normalised to
	// space-separated internally.
	// Use *string for the same presence-vs-empty reason as UpstreamOAuth.
	UpstreamOAuthScope *string `yaml:"upstream_oauth_scope,omitempty" json:"upstream_oauth_scope,omitempty"`
	// UpstreamOAuthGrant is the OAuth 2.0 grant type used for upstream token acquisition.
	// Valid values: "authorization_code" (user-interactive, default) or
	// "client_credentials" (service-to-service, no user interaction required).
	// Use *string for the same presence-vs-empty reason as UpstreamOAuth.
	UpstreamOAuthGrant *string `yaml:"upstream_oauth_grant,omitempty" json:"upstream_oauth_grant,omitempty"`
	// UpstreamProviderToken enables provider access token delegation for this route.
	// When true, the proxy resolves the authenticated subject's gateway provider token
	// (e.g. the GitHub user token in builtin mode) via EnsureFreshAccessTokenForSubject
	// and injects it as the upstream Authorization Bearer header instead of the gateway JWT.
	// Requires gateway authentication. Incompatible with upstream_bearer_token_env and upstream_oauth.
	UpstreamProviderToken bool `yaml:"upstream_provider_token,omitempty" json:"upstream_provider_token,omitempty"`
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

	Provider       string `yaml:"provider,omitempty"`
	ClientID       string `yaml:"client_id,omitempty"`
	ClientSecret   string `yaml:"client_secret,omitempty"`
	OIDCIssuerURL  string `yaml:"oidc_issuer_url,omitempty"`
	OIDCAudience   string `yaml:"oidc_audience,omitempty"`
	OIDCPrivateKey string `yaml:"oidc_private_key,omitempty"`
}

// GatewayConfig holds gateway-level settings that can be persisted in config.yaml.
type GatewayConfig struct {
	// BindAddr is the TCP address the HTTP listener binds to (e.g. "127.0.0.1:8080").
	// When empty, the runtime defaults to 127.0.0.1 with the resolved port.
	BindAddr string `yaml:"bind_addr,omitempty"`
	// PublicURL is the canonical base URL visible to OAuth clients and MCP clients
	// (e.g. "http://127.0.0.1:8080"). Used for redirect URIs, PRM, and discovery.
	PublicURL string `yaml:"public_url,omitempty"`
	// BaseURL is a deprecated alias for PublicURL. Use PublicURL for new deployments.
	// If set (and PublicURL is absent), BaseURL is copied to PublicURL with a warning.
	BaseURL string `yaml:"base_url,omitempty"`
	Port    string `yaml:"port,omitempty"`
	// OAuthScopes is the GitHub OAuth scope list forwarded to the provider.
	OAuthScopes string `yaml:"oauth_scopes,omitempty"`
	// TrustedProxies is a CIDR allowlist for reverse proxies whose
	// X-Forwarded-* headers may be reflected into downstream requests.
	TrustedProxies []string `yaml:"trusted_proxies,omitempty"`
	// TokenAudienceStrict rejects tokens that lack per-route audience metadata.
	// Leave false during the migration grace period for tokens issued before #57.
	TokenAudienceStrict bool `yaml:"token_audience_strict,omitempty"`
	// GitHubRefreshEnabled turns on transparent rotation of expiring GitHub
	// user access tokens (Phase A of issue #70). Safe to leave on when
	// the GitHub App is configured for non-expiring tokens — the rotation path
	// is dormant unless the upstream advertises refresh_token + expires_in.
	GitHubRefreshEnabled bool `yaml:"github_refresh_enabled,omitempty"`
	// AllowedRedirectHosts lists hostnames permitted in OAuth redirect_uris.
	// When set, replaces the built-in default list entirely.
	// Defaults to ["localhost", "127.0.0.1", "vscode.dev", "antigravity.google"].
	AllowedRedirectHosts []string `yaml:"allowed_redirect_hosts,omitempty"`
	// AllowedRedirectSchemes lists custom URL schemes (RFC 8252) permitted in
	// OAuth redirect_uris in addition to http and https. When set, replaces the
	// built-in default list entirely.
	// Defaults to ["antigravity", "antigravity-insiders"].
	AllowedRedirectSchemes []string `yaml:"allowed_redirect_schemes,omitempty"`
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
//  3. field empty/absent + OAUTH_CLIENT_SECRET (or legacy GITHUB_MCP_CLIENT_SECRET) env var set → encrypt, save to config, return
//  4. field empty + env var absent → return error
//
// The config file at configPath is updated in cases 2 and 3.
// The returned plaintext is never written to the log.
//
// When both OAUTH_CLIENT_SECRET and the legacy GITHUB_MCP_CLIENT_SECRET are set,
// the new variable wins and a deprecation warning is logged for the legacy one.
func MigrateSecret(configPath string, cfg *AppConfig, km *KeyMaterial, providerKind string) (string, error) {
	// Determine which secret to migrate based on providerKind and presence of fields
	useGeneric := providerKind == "oidc"
	if useGeneric && strings.TrimSpace(cfg.Auth.ClientSecret) == "" && strings.TrimSpace(cfg.Auth.GitHubClientSecret) != "" {
		useGeneric = false
	} else if !useGeneric && strings.TrimSpace(cfg.Auth.GitHubClientSecret) == "" && strings.TrimSpace(cfg.Auth.ClientSecret) != "" {
		useGeneric = true
	}

	var secret *string
	var fieldName string
	if useGeneric {
		secret = &cfg.Auth.ClientSecret
		fieldName = "client_secret"
	} else {
		secret = &cfg.Auth.GitHubClientSecret
		fieldName = "github_client_secret"
	}

	switch {
	case IsEncrypted(*secret):
		plaintext, err := DecryptField(km, *secret)
		if err != nil {
			return "", fmt.Errorf("decrypting %s: %w", fieldName, err)
		}
		return plaintext, nil

	case strings.TrimSpace(*secret) != "":
		plain := *secret
		slog.Info(fmt.Sprintf("plaintext %s found in config; encrypting and rewriting", fieldName))
		encrypted, err := EncryptField(km, plain)
		if err != nil {
			return "", fmt.Errorf("encrypting %s from config: %w", fieldName, err)
		}
		*secret = encrypted
		if err := SaveConfig(configPath, cfg); err != nil {
			return "", fmt.Errorf("saving config after encrypting %s: %w", fieldName, err)
		}
		return plain, nil

	default:
		envSecret, envSource, ok := resolveOAuthEnvSourced("OAUTH_CLIENT_SECRET", "GITHUB_MCP_CLIENT_SECRET")
		if ok {
			envSecret = strings.TrimSpace(envSecret)
			slog.Info("encrypting OAuth client secret from env and saving to config", "source", envSource)
			encrypted, err := EncryptField(km, envSecret)
			if err != nil {
				return "", fmt.Errorf("encrypting %s from env: %w", envSource, err)
			}
			*secret = encrypted
			if err := SaveConfig(configPath, cfg); err != nil {
				return "", fmt.Errorf("saving config after encrypting %s: %w", envSource, err)
			}
			return envSecret, nil
		}
		return "", fmt.Errorf("%s is required: set OAUTH_CLIENT_SECRET env var or provide an encrypted value in config.yaml", fieldName)
	}
}

// MigrateOIDCPrivateKey resolves the OIDC RSA private key, following this priority:
//
//  1. cfg.Auth.OIDCPrivateKey is "ENC[age:]..." → decrypt, parse PEM, and return *rsa.PrivateKey
//  2. field empty/absent → generate a new RSA 2048-bit key, PEM encode, encrypt, save to config, and return
func MigrateOIDCPrivateKey(configPath string, cfg *AppConfig, km *KeyMaterial) (*rsa.PrivateKey, error) {
	keyField := &cfg.Auth.OIDCPrivateKey
	if IsEncrypted(*keyField) {
		plaintext, err := DecryptField(km, *keyField)
		if err != nil {
			return nil, fmt.Errorf("decrypting oidc_private_key: %w", err)
		}
		block, _ := pem.Decode([]byte(plaintext))
		if block == nil || block.Type != "RSA PRIVATE KEY" {
			return nil, fmt.Errorf("invalid PEM block type for RSA private key")
		}
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing RSA private key: %w", err)
		}
		return privKey, nil
	}

	// Generate a new RSA 2048-bit key
	slog.Info("no OIDC private key found; generating a new RSA key")
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generating RSA private key: %w", err)
	}

	privBytes := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privBytes,
	}
	pemBytes := pem.EncodeToMemory(pemBlock)

	encrypted, err := EncryptField(km, string(pemBytes))
	if err != nil {
		return nil, fmt.Errorf("encrypting generated RSA private key: %w", err)
	}

	*keyField = encrypted
	if err := SaveConfig(configPath, cfg); err != nil {
		slog.Warn("failed to save generated OIDC private key to config; using in-memory key (will not persist across restarts)", "err", err)
	} else {
		slog.Info("saved generated OIDC private key to config")
	}

	return privKey, nil
}

