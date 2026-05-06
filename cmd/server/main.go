package main

import (
	"fmt"
	"log/slog"
	"net"
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
	"github.com/scottlz0310/mcp-gateway/internal/setup"
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

	// Load YAML config.
	appCfg, err := appconfig.LoadConfig(cfg.configPath)
	if err != nil {
		slog.Error("failed to load config file", "path", cfg.configPath, "err", err)
		os.Exit(1)
	}

	// Parse routes from env early so setup.IsSetupRequired can see them.
	envRoutes, err := router.ParseEnv()
	if err != nil {
		slog.Error("invalid route configuration", "err", err)
		os.Exit(1)
	}

	// Also apply the legacy GITHUB_MCP_UPSTREAM_URL fallback before the setup check,
	// so IsSetupRequired does not fire when routes are only provided via the legacy var.
	if len(envRoutes) == 0 && strings.TrimSpace(cfg.upstreamURL) != "" {
		u, err := url.Parse(cfg.upstreamURL)
		if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
			slog.Error("invalid upstream URL", "url", cfg.upstreamURL, "err", err)
			os.Exit(1)
		}
		envRoutes = []router.Route{{Name: "default", Prefix: "/mcp", Upstream: u}}
		slog.Warn("GITHUB_MCP_UPSTREAM_URL is deprecated; use ROUTE_<NAME>=<prefix>|<url> instead")
	}

	// First-run wizard: if any required value is missing, enter setup mode.
	envClientID := os.Getenv("GITHUB_MCP_CLIENT_ID")
	envSecret := os.Getenv("GITHUB_MCP_CLIENT_SECRET")

	// Deprecation warning: MCP_GATEWAY_BASE_URL is superseded by MCP_GATEWAY_PUBLIC_URL.
	// Warn whenever BASE_URL is set, regardless of whether PUBLIC_URL is also present.
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_BASE_URL")) != "" {
		slog.Warn("MCP_GATEWAY_BASE_URL is deprecated; use MCP_GATEWAY_PUBLIC_URL instead",
			"hint", "MCP_GATEWAY_BASE_URL will be removed in a future release")
	}

	// Apply config.yaml gateway overrides (priority: env var > config.yaml > loadConfig default).
	// publicURL: MCP_GATEWAY_PUBLIC_URL > MCP_GATEWAY_BASE_URL > yaml public_url > yaml base_url > default
	if strings.TrimSpace(appCfg.Gateway.BaseURL) != "" {
		slog.Warn("gateway.base_url in config.yaml is deprecated; use gateway.public_url instead")
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_PUBLIC_URL")) == "" &&
		strings.TrimSpace(os.Getenv("MCP_GATEWAY_BASE_URL")) == "" {
		if strings.TrimSpace(appCfg.Gateway.PublicURL) != "" {
			cfg.publicURL = appCfg.Gateway.PublicURL
		} else if strings.TrimSpace(appCfg.Gateway.BaseURL) != "" {
			cfg.publicURL = appCfg.Gateway.BaseURL
		}
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_PORT")) == "" && strings.TrimSpace(appCfg.Gateway.Port) != "" {
		cfg.port = appCfg.Gateway.Port
	}
	// bindAddr: MCP_GATEWAY_BIND_ADDR > yaml bind_addr > 127.0.0.1:<resolved port>
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_BIND_ADDR")) == "" {
		if strings.TrimSpace(appCfg.Gateway.BindAddr) != "" {
			cfg.bindAddr = appCfg.Gateway.BindAddr
		} else {
			cfg.bindAddr = "127.0.0.1:" + cfg.port
		}
	}
	// If publicURL was not explicitly set (no env, no yaml), recompute the default from the
	// resolved bind address so that a non-default port in BIND_ADDR or gateway.bind_addr is
	// reflected in OAuth redirects and discovery metadata.
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_PUBLIC_URL")) == "" &&
		strings.TrimSpace(os.Getenv("MCP_GATEWAY_BASE_URL")) == "" &&
		strings.TrimSpace(appCfg.Gateway.PublicURL) == "" &&
		strings.TrimSpace(appCfg.Gateway.BaseURL) == "" {
		_, bindPort, err := net.SplitHostPort(cfg.bindAddr)
		if err == nil && strings.TrimSpace(bindPort) != "" {
			cfg.publicURL = "http://127.0.0.1:" + bindPort
		} else {
			cfg.publicURL = "http://127.0.0.1:" + cfg.port
		}
	}
	if strings.TrimSpace(os.Getenv("GITHUB_MCP_OAUTH_SCOPES")) == "" && strings.TrimSpace(appCfg.Gateway.OAuthScopes) != "" {
		cfg.oauthScopes = appCfg.Gateway.OAuthScopes
	}

	if setup.IsSetupRequired(appCfg, envClientID, envSecret, envRoutes) {
		runSetupWizard(cfg, appCfg, km, envClientID, envSecret, len(envRoutes) > 0)
		// runSetupWizard only returns if the listener fails immediately.
		os.Exit(1)
	}

	// Validate required startup inputs before any config writes.
	// This prevents a mistyped env var from being encrypted and saved to config.yaml
	// on a first boot that would otherwise fail (e.g. missing CLIENT_ID or routes).

	// GitHub client ID: env var takes precedence over config file.
	githubClientID := getEnv("GITHUB_MCP_CLIENT_ID", appCfg.Auth.GitHubClientID)
	if strings.TrimSpace(githubClientID) == "" {
		slog.Error("required value not set: provide GITHUB_MCP_CLIENT_ID env var or auth.github_client_id in config.yaml")
		os.Exit(1)
	}

	routes := envRoutes

	// Fall back to routes stored in config.yaml (written by the setup wizard).
	if len(routes) == 0 && len(appCfg.Routes) > 0 {
		cfgRoutes, err := router.ParseFromConfig(appCfg.Routes)
		if err != nil {
			slog.Error("invalid routes in config.yaml", "err", err)
			os.Exit(1)
		}
		routes = cfgRoutes
	}

	if len(routes) == 0 {
		slog.Error("no routes configured: set ROUTE_<NAME>=<prefix>|<upstream_url>")
		os.Exit(1)
	}

	// Resolve the GitHub client secret (and persist it encrypted if sourced from env).
	// Only runs after the above validations pass to avoid making a wrong value sticky.
	githubClientSecret, err := appconfig.MigrateSecret(cfg.configPath, appCfg, km)
	if err != nil {
		slog.Error("github_client_secret is unavailable", "err", err)
		os.Exit(1)
	}

	cfg.githubClientID = githubClientID
	cfg.githubClientSecret = githubClientSecret

	prov, err := provider.New(provider.Config{
		Kind:         "github",
		ClientID:     cfg.githubClientID,
		ClientSecret: cfg.githubClientSecret,
		RedirectURI:  strings.TrimRight(cfg.publicURL, "/") + "/callback",
		Scopes:       cfg.oauthScopes,
	})
	if err != nil {
		slog.Error("provider init failed", "err", err)
		os.Exit(1)
	}

	oauthHandler, err := auth.NewHandler(auth.Config{
		BaseURL:        cfg.publicURL,
		SessionTTL:     time.Duration(cfg.sessionTTLMin) * time.Minute,
		CacheTTL:       time.Duration(cfg.tokenCacheTTLMin) * time.Minute,
		ExpiresIn:      time.Duration(cfg.tokenExpiresInSec) * time.Second,
		TokenStorePath: cfg.tokenStorePath,
	}, prov)
	if err != nil {
		slog.Error("auth handler init failed", "err", err)
		os.Exit(1)
	}

	publicURL := strings.TrimRight(cfg.publicURL, "/")

	mux := http.NewServeMux()

	// OAuth façade endpoints (no auth required).
	// The path-less /.well-known/oauth-protected-resource is preserved for
	// backward compatibility (gateway-wide PRM); per-route PRMs are registered
	// inside the route loop below per MCP Authorization Spec 2025-06-18.
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
	// Each authenticated route also exposes its own RFC 9728 PRM document at
	// /.well-known/oauth-protected-resource{prefix}, and 401 responses point
	// resource_metadata at that route-scoped URL.
	for _, route := range routes {
		h := proxy.NewHandler(route.Upstream, oauthHandler)
		var wrapped http.Handler
		if route.NoAuth {
			wrapped = h
		} else {
			// For a root prefix ("/"), the gateway-wide PRM registered above
			// already covers the route (resource == public_url). Skip per-route
			// registration to avoid (a) ServeMux duplicate-pattern panic, and
			// (b) a trailing-slash subtree pattern that would shadow other
			// per-route PRM URLs. The middleware then falls back to the
			// gateway-wide resource_metadata URL via WithBaseURL.
			authOpts := []middleware.AuthOption{middleware.WithBaseURL(cfg.publicURL)}
			if route.Prefix != "/" {
				routeResource := publicURL + route.Prefix
				routePRMPath := "/.well-known/oauth-protected-resource" + route.Prefix
				mux.HandleFunc("GET "+routePRMPath, oauthHandler.RouteProtectedResourceMetadata(routeResource))
				authOpts = append(authOpts, middleware.WithResourceMetadataURL(publicURL+routePRMPath))
			}
			routeAuth := middleware.Auth(oauthHandler, authOpts...)
			wrapped = routeAuth(h)
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

	slog.Info("mcp-gateway starting",
		"bind_addr", cfg.bindAddr,
		"public_url", cfg.publicURL,
		"provider", prov.Name(),
		"routes", len(routes),
	)

	server := &http.Server{
		Addr:              cfg.bindAddr,
		Handler:           middleware.Logger()(mux),
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

// runSetupWizard starts an HTTP server that serves only the /setup endpoint.
// It blocks until a successful POST /setup causes the process to exit (so the
// supervisor can restart in normal mode), or until the listener fails.
func runSetupWizard(cfg config, appCfg *appconfig.AppConfig, km *appconfig.KeyMaterial, envClientID, envSecret string, hasEnvRoutes bool) {
	mgr, err := setup.New()
	if err != nil {
		slog.Error("failed to create setup token", "err", err)
		return
	}

	setupURL := strings.TrimRight(cfg.publicURL, "/") + "/setup?token=" + mgr.Token()

	slog.Warn("mcp-gateway starting in setup mode — configure via /setup",
		"setup_url", setupURL,
		"token", mgr.Token(),
	)

	h := setup.NewHandler(mgr, appCfg, cfg.configPath, km, func() {
		slog.Info("setup complete; restarting to apply configuration")
		os.Exit(0)
	}, setup.WithEnvValues(envClientID, envSecret, hasEnvRoutes))

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	// All other paths return 503 directing operators to /setup.
	mux.Handle("/", setup.UnconfiguredHandler(setupURL))

	server := &http.Server{
		Addr:              cfg.bindAddr,
		Handler:           middleware.Logger()(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	slog.Info("setup wizard listening", "bind_addr", cfg.bindAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("setup server error", "err", err)
	}
}

type config struct {
	githubClientID     string
	githubClientSecret string
	// publicURL is the canonical base URL visible to OAuth / MCP clients.
	// Replaces the deprecated baseURL / MCP_GATEWAY_BASE_URL.
	publicURL          string
	// bindAddr is the TCP address the HTTP listener binds to (host:port).
	bindAddr           string
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
	port := getEnv("MCP_GATEWAY_PORT", "8080")

	// publicURL resolution: MCP_GATEWAY_PUBLIC_URL > MCP_GATEWAY_BASE_URL > default.
	// Deprecation warning for MCP_GATEWAY_BASE_URL is emitted in main() after logger init.
	publicURL := getEnv("MCP_GATEWAY_PUBLIC_URL",
		getEnv("MCP_GATEWAY_BASE_URL", "http://127.0.0.1:"+port))

	// bindAddr defaults to loopback; Docker deployments should set MCP_GATEWAY_BIND_ADDR=0.0.0.0:<port>.
	bindAddr := getEnv("MCP_GATEWAY_BIND_ADDR", "127.0.0.1:"+port)

	return config{
		// githubClientID and githubClientSecret are resolved after key/config loading in main().
		publicURL:         publicURL,
		bindAddr:          bindAddr,
		port:              port,
		oauthScopes:       getEnv("GITHUB_MCP_OAUTH_SCOPES", "repo,user"),
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
