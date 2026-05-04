package main

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
	"github.com/scottlz0310/mcp-gateway/internal/proxy"
	"github.com/scottlz0310/mcp-gateway/internal/router"
)

func main() {
	// Initialize logger before loadConfig so mustEnv failures use the JSON handler.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLogLevel(getEnv("LOG_LEVEL", "info")),
	})))

	cfg := loadConfig()

	// Load or generate the encryption key.
	masterKey := []byte(getEnv("MCP_GATEWAY_MASTER_KEY", os.Getenv("MCP_MASTER_KEY")))
	if len(strings.TrimSpace(string(masterKey))) == 0 {
		masterKey = nil
	}
	km, err := appconfig.LoadKey(cfg.keyPath, masterKey)
	if err != nil {
		slog.Error("failed to load gateway encryption key", "path", cfg.keyPath, "err", err)
		os.Exit(1)
	}

	// Load YAML config and resolve the GitHub client secret.
	appCfg, err := appconfig.LoadConfig(cfg.configPath)
	if err != nil {
		slog.Error("failed to load config file", "path", cfg.configPath, "err", err)
		os.Exit(1)
	}

	githubClientSecret, err := appconfig.MigrateSecret(cfg.configPath, appCfg, km)
	if err != nil {
		slog.Error("github_client_secret is unavailable", "err", err)
		os.Exit(1)
	}

	// GitHub client ID: env var takes precedence over config file.
	githubClientID := getEnv("GITHUB_MCP_CLIENT_ID", appCfg.Auth.GitHubClientID)
	if strings.TrimSpace(githubClientID) == "" {
		slog.Error("required value not set: provide GITHUB_MCP_CLIENT_ID env var or auth.github_client_id in config.yaml")
		os.Exit(1)
	}

	cfg.githubClientID = githubClientID
	cfg.githubClientSecret = githubClientSecret

	// Apply config.yaml gateway overrides (priority: env var > config.yaml > built-in default).
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_BASE_URL")) == "" && strings.TrimSpace(appCfg.Gateway.BaseURL) != "" {
		cfg.baseURL = appCfg.Gateway.BaseURL
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_PORT")) == "" && strings.TrimSpace(appCfg.Gateway.Port) != "" {
		cfg.port = appCfg.Gateway.Port
	}
	if strings.TrimSpace(os.Getenv("GITHUB_MCP_OAUTH_SCOPES")) == "" && strings.TrimSpace(appCfg.Gateway.OAuthScopes) != "" {
		cfg.oauthScopes = appCfg.Gateway.OAuthScopes
	}

	routes, err := router.ParseEnv()
	if err != nil {
		slog.Error("invalid route configuration", "err", err)
		os.Exit(1)
	}

	// Backward-compat: fall back to legacy single-upstream env var.
	if len(routes) == 0 && cfg.upstreamURL != "" {
		u, err := url.Parse(cfg.upstreamURL)
		if err != nil {
			slog.Error("invalid upstream URL", "url", cfg.upstreamURL, "err", err)
			os.Exit(1)
		}
		if u.Scheme == "" || u.Host == "" {
			slog.Error("upstream URL must be absolute with scheme and host", "url", cfg.upstreamURL)
			os.Exit(1)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			slog.Error("upstream URL scheme must be http or https", "url", cfg.upstreamURL)
			os.Exit(1)
		}
		routes = []router.Route{{Name: "default", Prefix: "/mcp", Upstream: u}}
		slog.Warn("GITHUB_MCP_UPSTREAM_URL is deprecated; use ROUTE_<NAME>=<prefix>|<url> instead")
	}

	if len(routes) == 0 {
		slog.Error("no routes configured: set ROUTE_<NAME>=<prefix>|<upstream_url>")
		os.Exit(1)
	}

	prov, err := provider.New(provider.Config{
		Kind:         "github",
		ClientID:     cfg.githubClientID,
		ClientSecret: cfg.githubClientSecret,
		RedirectURI:  strings.TrimRight(cfg.baseURL, "/") + "/callback",
		Scopes:       cfg.oauthScopes,
	})
	if err != nil {
		slog.Error("provider init failed", "err", err)
		os.Exit(1)
	}

	oauthHandler, err := auth.NewHandler(auth.Config{
		BaseURL:        cfg.baseURL,
		SessionTTL:     time.Duration(cfg.sessionTTLMin) * time.Minute,
		CacheTTL:       time.Duration(cfg.tokenCacheTTLMin) * time.Minute,
		ExpiresIn:      time.Duration(cfg.tokenExpiresInSec) * time.Second,
		TokenStorePath: cfg.tokenStorePath,
	}, prov)
	if err != nil {
		slog.Error("auth handler init failed", "err", err)
		os.Exit(1)
	}

	authMiddleware := middleware.Auth(oauthHandler, middleware.WithBaseURL(cfg.baseURL))

	mux := http.NewServeMux()

	// OAuth façade endpoints (no auth required).
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", oauthHandler.ProtectedResourceMetadata)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", oauthHandler.Discovery)
	mux.HandleFunc("GET /authorize", oauthHandler.Authorize)
	mux.HandleFunc("GET /callback", oauthHandler.Callback)
	mux.HandleFunc("POST /token", oauthHandler.Token)
	mux.HandleFunc("POST /register", oauthHandler.Register)
	mux.HandleFunc("POST /device_authorization", oauthHandler.DeviceAuthorize)

	// Health check.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
	})

	// Proxy routes — apply auth middleware unless the route opts out.
	for _, route := range routes {
		h := proxy.NewHandler(route.Upstream, oauthHandler)
		var wrapped http.Handler
		if route.NoAuth {
			wrapped = h
		} else {
			wrapped = authMiddleware(h)
		}
		mux.Handle(route.Prefix, wrapped)
		mux.Handle(route.Prefix+"/", wrapped)
		slog.Info("registered route",
			"name", route.Name,
			"prefix", route.Prefix,
			"upstream", route.Upstream.String(),
			"auth_required", !route.NoAuth,
		)
	}

	addr := ":" + cfg.port
	slog.Info("mcp-gateway starting",
		"addr", addr,
		"base_url", cfg.baseURL,
		"provider", prov.Name(),
		"routes", len(routes),
	)

	server := &http.Server{
		Addr:              addr,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // unlimited: MCP streaming responses may be long-lived
		IdleTimeout:       120 * time.Second,
	}
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

type config struct {
	githubClientID     string
	githubClientSecret string
	baseURL            string
	oauthScopes        string
	port               string
	logLevel           string
	upstreamURL        string // deprecated; prefer ROUTE_* env vars
	sessionTTLMin      int
	tokenCacheTTLMin   int
	tokenExpiresInSec  int
	tokenStorePath     string
	keyPath            string
	configPath         string
}

func loadConfig() config {
	return config{
		// githubClientID and githubClientSecret are resolved after key/config loading in main().
		baseURL:           getEnv("MCP_GATEWAY_BASE_URL", "http://localhost:8080"),
		oauthScopes:       getEnv("GITHUB_MCP_OAUTH_SCOPES", "repo,user"),
		port:              getEnv("MCP_GATEWAY_PORT", "8080"),
		logLevel:          getEnv("LOG_LEVEL", "info"),
		upstreamURL:       getEnv("GITHUB_MCP_UPSTREAM_URL", ""),
		sessionTTLMin:     getEnvInt("SESSION_TTL_MIN", 10),
		tokenCacheTTLMin:  getEnvInt("TOKEN_CACHE_TTL_MIN", 30),
		tokenExpiresInSec: getEnvInt("TOKEN_EXPIRES_IN_SEC", 7776000), // 90 days
		tokenStorePath:    lookupEnv("MCP_GATEWAY_TOKEN_STORE_PATH", "/data/tokens.json"),
		keyPath:           getEnv("MCP_GATEWAY_KEY_PATH", "./gateway.key"),
		configPath:        getEnv("MCP_CONFIG_FILE", "./config.yaml"),
	}
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// lookupEnv returns the trimmed env value if the variable is set (even if empty),
// otherwise returns fallback. Use instead of getEnv when an empty value has meaning
// (e.g. MCP_GATEWAY_TOKEN_STORE_PATH="" disables persistence).
func lookupEnv(key, fallback string) string {
	if v, ok := os.LookupEnv(key); ok {
		return strings.TrimSpace(v)
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return fallback
}

func parseLogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
