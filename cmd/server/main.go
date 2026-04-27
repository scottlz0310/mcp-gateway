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

	oauthHandler := auth.NewHandler(auth.Config{
		GitHubClientID:     cfg.githubClientID,
		GitHubClientSecret: cfg.githubClientSecret,
		BaseURL:            cfg.baseURL,
		Scopes:             cfg.oauthScopes,
		SessionTTL:         time.Duration(cfg.sessionTTLMin) * time.Minute,
		CacheTTL:           time.Duration(cfg.tokenCacheTTLMin) * time.Minute,
		ExpiresIn:          time.Duration(cfg.tokenExpiresInSec) * time.Second,
	})

	authMiddleware := middleware.Auth(oauthHandler)

	mux := http.NewServeMux()

	// OAuth façade endpoints (no auth required).
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

	// Authenticated proxy routes.
	for _, route := range routes {
		h := proxy.NewHandler(route.Upstream, oauthHandler)
		mux.Handle(route.Prefix, authMiddleware(h))
		mux.Handle(route.Prefix+"/", authMiddleware(h))
		slog.Info("registered route",
			"name", route.Name,
			"prefix", route.Prefix,
			"upstream", route.Upstream.String(),
		)
	}

	addr := ":" + cfg.port
	slog.Info("mcp-gateway starting",
		"addr", addr,
		"base_url", cfg.baseURL,
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
}

func loadConfig() config {
	return config{
		githubClientID:     mustEnv("GITHUB_MCP_CLIENT_ID"),
		githubClientSecret: mustEnv("GITHUB_MCP_CLIENT_SECRET"),
		baseURL:            getEnv("MCP_GATEWAY_BASE_URL", "http://localhost:8080"),
		oauthScopes:        getEnv("GITHUB_MCP_OAUTH_SCOPES", "repo,user"),
		port:               getEnv("MCP_GATEWAY_PORT", "8080"),
		logLevel:           getEnv("LOG_LEVEL", "info"),
		upstreamURL:        getEnv("GITHUB_MCP_UPSTREAM_URL", ""),
		sessionTTLMin:      getEnvInt("SESSION_TTL_MIN", 10),
		tokenCacheTTLMin:   getEnvInt("TOKEN_CACHE_TTL_MIN", 30),
		tokenExpiresInSec:  getEnvInt("TOKEN_EXPIRES_IN_SEC", 7776000), // 90 days
	}
}

func mustEnv(key string) string {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		slog.Error("required environment variable not set", "key", key)
		os.Exit(1)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
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
