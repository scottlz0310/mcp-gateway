package main

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/internalapi"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
	"github.com/scottlz0310/mcp-gateway/internal/proxy"
	"github.com/scottlz0310/mcp-gateway/internal/router"
	"github.com/scottlz0310/mcp-gateway/internal/setup"
	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
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
	envClientID, _ := appconfig.ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	envSecret, _ := appconfig.ResolveOAuthEnv("OAUTH_CLIENT_SECRET", "GITHUB_MCP_CLIENT_SECRET")

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
	if _, ok := appconfig.ResolveOAuthEnv("OAUTH_SCOPES", "GITHUB_MCP_OAUTH_SCOPES"); !ok && strings.TrimSpace(appCfg.Gateway.OAuthScopes) != "" {
		cfg.oauthScopes = appCfg.Gateway.OAuthScopes
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_TRUSTED_PROXIES")) == "" && len(appCfg.Gateway.TrustedProxies) > 0 {
		cfg.trustedProxyCIDRs = appCfg.Gateway.TrustedProxies
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_TOKEN_AUDIENCE_STRICT")) == "" {
		cfg.tokenAudienceStrict = appCfg.Gateway.TokenAudienceStrict
	}
	if _, set := os.LookupEnv("MCP_GATEWAY_GITHUB_REFRESH_ENABLED"); !set {
		cfg.githubRefreshEnabled = appCfg.Gateway.GitHubRefreshEnabled
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS")) == "" && len(appCfg.Gateway.AllowedRedirectHosts) > 0 {
		cfg.allowedRedirectHosts = appCfg.Gateway.AllowedRedirectHosts
	}
	if strings.TrimSpace(os.Getenv("MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES")) == "" && len(appCfg.Gateway.AllowedRedirectSchemes) > 0 {
		cfg.allowedRedirectSchemes = appCfg.Gateway.AllowedRedirectSchemes
	}
	// Apply config.yaml OAuth provider overrides
	if strings.TrimSpace(os.Getenv("OAUTH_PROVIDER")) == "" && strings.TrimSpace(appCfg.Auth.Provider) != "" {
		cfg.oauthProvider = appCfg.Auth.Provider
	}
	// Apply config.yaml OIDC overrides
	if strings.TrimSpace(os.Getenv("OAUTH_ISSUER_URL")) == "" && strings.TrimSpace(appCfg.Auth.OIDCIssuerURL) != "" {
		cfg.oidcIssuerURL = appCfg.Auth.OIDCIssuerURL
	}
	if strings.TrimSpace(os.Getenv("OAUTH_AUDIENCE")) == "" && strings.TrimSpace(appCfg.Auth.OIDCAudience) != "" {
		cfg.oidcAudience = appCfg.Auth.OIDCAudience
	}

	trustedProxies, err := middleware.ParseTrustedProxyCIDRs(cfg.trustedProxyCIDRs)
	if err != nil {
		slog.Error("invalid trusted proxy configuration", "err", err)
		os.Exit(1)
	}

	if setup.IsSetupRequired(appCfg, envClientID, envSecret, envRoutes) {
		runSetupWizard(cfg, appCfg, km, envClientID, envSecret, len(envRoutes) > 0, trustedProxies)
		// runSetupWizard only returns if the listener fails immediately.
		os.Exit(1)
	}

	// Validate required startup inputs before any config writes.
	// This prevents a mistyped env var from being encrypted and saved to config.yaml
	// on a first boot that would otherwise fail (e.g. missing CLIENT_ID or routes).

	// Client ID: env var (OAUTH_CLIENT_ID or legacy GITHUB_MCP_CLIENT_ID) takes precedence over config file.
	clientID := envClientID
	if strings.TrimSpace(clientID) == "" {
		if cfg.oauthProvider == "oidc" && strings.TrimSpace(appCfg.Auth.ClientID) != "" {
			clientID = appCfg.Auth.ClientID
		} else if strings.TrimSpace(appCfg.Auth.GitHubClientID) != "" {
			clientID = appCfg.Auth.GitHubClientID
		} else {
			clientID = appCfg.Auth.ClientID
		}
	}
	if strings.TrimSpace(clientID) == "" {
		slog.Error("required value not set: provide OAUTH_CLIENT_ID env var or auth.client_id/auth.github_client_id in config.yaml")
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

	// Resolve the client secret (and persist it encrypted if sourced from env).
	// Only runs after the above validations pass to avoid making a wrong value sticky.
	clientSecret, err := appconfig.MigrateSecret(cfg.configPath, appCfg, km, cfg.oauthProvider)
	if err != nil {
		slog.Error("client secret is unavailable", "err", err)
		os.Exit(1)
	}

	cfg.githubClientID = clientID
	cfg.githubClientSecret = clientSecret

	prov, err := provider.New(provider.Config{
		Kind:          cfg.oauthProvider,
		ClientID:      cfg.githubClientID,
		ClientSecret:  cfg.githubClientSecret,
		RedirectURI:   strings.TrimRight(cfg.publicURL, "/") + "/callback",
		Scopes:        cfg.oauthScopes,
		OIDCIssuerURL: cfg.oidcIssuerURL,
		OIDCAudience:  cfg.oidcAudience,
	})
	if err != nil {
		slog.Error("provider init failed", "err", err)
		os.Exit(1)
	}

	oidcPrivateKey, err := appconfig.MigrateOIDCPrivateKey(cfg.configPath, appCfg, km)
	if err != nil {
		slog.Error("OIDC private key migration failed", "err", err)
		os.Exit(1)
	}

	auditConfig, err := authaudit.FromEnvironment()
	if err != nil {
		slog.Error("auth audit configuration invalid", "err", err)
		os.Exit(1)
	}
	auditRecorder, err := authaudit.New(auditConfig)
	if err != nil {
		slog.Error("auth audit initialization failed", "path", auditConfig.Path, "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := auditRecorder.Close(); err != nil {
			slog.Error("auth audit shutdown failed", "err", err)
		}
	}()

	oauthHandler, err := auth.NewHandler(auth.Config{
		BaseURL:              cfg.publicURL,
		SessionTTL:           time.Duration(cfg.sessionTTLMin) * time.Minute,
		CacheTTL:             time.Duration(cfg.tokenCacheTTLMin) * time.Minute,
		ExpiresIn:            time.Duration(cfg.tokenExpiresInSec) * time.Second,
		TokenStorePath:       cfg.tokenStorePath,
		ResourceAudienceMap:  buildResourceAudienceMap(routes, cfg.publicURL),
		TokenAudienceStrict:  cfg.tokenAudienceStrict,
		GitHubRefreshEnabled: cfg.githubRefreshEnabled,
		OIDCPrivateKey:       oidcPrivateKey,
		AllowedRedirectHosts:   cfg.allowedRedirectHosts,
		AllowedRedirectSchemes: cfg.allowedRedirectSchemes,
	}, prov, auth.WithAuditRecorder(auditRecorder))
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
	mux.HandleFunc("GET /.well-known/openid-configuration", oauthHandler.OIDCDiscovery)
	mux.HandleFunc("GET /jwks", oauthHandler.JWKS)
	mux.HandleFunc("GET /userinfo", oauthHandler.UserInfo)
	mux.HandleFunc("GET /authorize", oauthHandler.Authorize)
	mux.HandleFunc("GET /callback", oauthHandler.Callback)
	mux.HandleFunc("POST /token", oauthHandler.Token)
	mux.HandleFunc("POST /register", oauthHandler.Register)
	mux.HandleFunc("POST /device_authorization", oauthHandler.DeviceAuthorize)
	mux.HandleFunc("GET /activate", oauthHandler.Activate)
	mux.HandleFunc("POST /activate", oauthHandler.ActivateSubmit)
	mux.HandleFunc("GET /device_callback", oauthHandler.DeviceCallback)

	// Health check.
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintln(w, `{"status":"ok"}`)
	})

	// Initialize upstream OAuth components when any route has upstream_oauth configured.
	var upstreamManager *upstreamoauth.Manager
	var upstreamStateStore upstreamoauth.StateStore
	var upstreamTokenStore auth.UpstreamTokenStore
	var upstreamRefresher *upstreamoauth.Refresher
	for _, r := range routes {
		if r.UpstreamOAuth != "" {
			clientStore, err := upstreamoauth.NewFileClientStore(cfg.upstreamClientStorePath)
			if err != nil {
				slog.Error("failed to initialize upstream client store", "err", err)
				os.Exit(1)
			}
			upstreamManager = upstreamoauth.NewManager(clientStore, publicURL)
			upstreamStateStore = upstreamoauth.NewStateStore()
			upstreamTokenStore, err = auth.NewFileUpstreamTokenStore(cfg.upstreamTokenStorePath)
			if err != nil {
				slog.Error("failed to initialize upstream token store", "err", err)
				os.Exit(1)
			}
			upstreamRefresher = upstreamoauth.NewRefresher(upstreamTokenStore, upstreamManager, nil)
			callbackHandler := upstreamoauth.NewCallbackHandler(
				upstreamStateStore, upstreamManager, upstreamTokenStore, publicURL, nil,
			)
			mux.Handle("GET /upstream/callback/{routeName}", callbackHandler)
			slog.Info("upstream OAuth callback endpoint registered", "path", "/upstream/callback/{routeName}")

			// Background sweeper: remove expired state entries and token records
			// so that abandoned auth flows do not accumulate indefinitely.
			go func() {
				t := time.NewTicker(5 * time.Minute)
				defer t.Stop()
				for range t.C {
					upstreamStateStore.Sweep()
					if err := upstreamTokenStore.Sweep(); err != nil {
						slog.Warn("upstream token store sweep failed", "err", err)
					}
				}
			}()
			break
		}
	}

	// Proxy routes — apply auth middleware unless the route opts out.
	// Each authenticated route also exposes its own RFC 9728 PRM document at
	// /.well-known/oauth-protected-resource{prefix}, and 401 responses point
	// resource_metadata at that route-scoped URL.
	for _, route := range routes {
		var upstreamOAuthOpts *proxy.UpstreamOAuthOptions
		if route.UpstreamOAuth != "" && upstreamTokenStore != nil {
			upstreamOAuthOpts = &proxy.UpstreamOAuthOptions{
				TokenStore: upstreamTokenStore,
				RouteName:  route.Name,
				Refresher:  upstreamRefresher,
			}
		}
		h := proxy.NewHandler(route.Upstream, oauthHandler, route.UpstreamBearerTokenEnv, route.Prefix, upstreamOAuthOpts)
		var wrapped http.Handler
		if route.NoAuth {
			wrapped = h
		} else {
			// routeResource is the RFC 9728 PRM identifier (URL form) used both for
			// discovery metadata and (via buildResourceAudienceMap) for JWT aud resolution.
			routeResource := publicURL
			if route.Prefix != "/" {
				routeResource = publicURL + route.Prefix
			}
			// For a root prefix ("/"), the gateway-wide PRM registered above
			// already covers the route (resource == public_url). Skip per-route
			// registration to avoid (a) ServeMux duplicate-pattern panic, and
			// (b) a trailing-slash subtree pattern that would shadow other
			// per-route PRM URLs. The middleware then falls back to the
			// gateway-wide resource_metadata URL via WithBaseURL.
			authOpts := []middleware.AuthOption{
				middleware.WithBaseURL(cfg.publicURL),
				middleware.WithAudience(route.RequiredAudience),
			}
			if route.Prefix != "/" {
				routePRMPath := "/.well-known/oauth-protected-resource" + route.Prefix
				mux.HandleFunc("GET "+routePRMPath, oauthHandler.RouteProtectedResourceMetadata(routeResource))
				authOpts = append(authOpts, middleware.WithResourceMetadataURL(publicURL+routePRMPath))
			}
			routeAuth := middleware.Auth(oauthHandler, authOpts...)

			// For routes with upstream OAuth, insert the authorize middleware
			// between the gateway auth middleware and the proxy handler so that
			// authenticated users without a valid upstream token are redirected
			// to the upstream authorization endpoint.
			proxyHandler := http.Handler(h)
			if route.UpstreamOAuth != "" && upstreamManager != nil {
				proxyHandler = upstreamoauth.NewAuthorizeMiddleware(
					route.Name,
					route.UpstreamOAuth,
					route.UpstreamOAuthScope,
					route.UpstreamOAuthGrant,
					route.Upstream.String(),
					upstreamManager,
					upstreamStateStore,
					upstreamTokenStore,
					publicURL,
				)(h)
			}
			// For routes with upstream_provider_token=true, resolve the subject's
			// gateway provider access token and inject it as the upstream Bearer token.
			// Placed between auth middleware and the proxy so that the subject identity
			// is available in context before the provider token lookup runs.
			if route.UpstreamProviderToken {
				// Always include the resource_metadata URL so MCP clients can discover
				// the gateway OAuth flow on 401. For "/" prefix routes, use the
				// gateway-wide PRM URL; for sub-path routes, use the per-route PRM URL.
				providerTokenResourceMetadataURL := publicURL + "/.well-known/oauth-protected-resource"
				if route.Prefix != "/" {
					providerTokenResourceMetadataURL += route.Prefix
				}
				proxyHandler = proxy.NewProviderTokenMiddleware(oauthHandler, providerTokenResourceMetadataURL, proxyHandler)
			}
			wrapped = routeAuth(proxyHandler)
		}
		mux.Handle(route.Prefix, wrapped)
		mux.Handle(route.Prefix+"/", wrapped)
		slog.Info("registered route",
			"name", route.Name,
			"prefix", route.Prefix,
			"upstream", route.Upstream.String(),
			"auth_required", !route.NoAuth,
			"upstream_bearer_token_env", route.UpstreamBearerTokenEnv != "",
			"upstream_oauth", route.UpstreamOAuth != "",
			"upstream_provider_token", route.UpstreamProviderToken,
		)
	}

	slog.Info("mcp-gateway starting",
		"bind_addr", cfg.bindAddr,
		"public_url", cfg.publicURL,
		"provider", prov.Name(),
		"routes", len(routes),
		"trusted_proxies", len(trustedProxies),
		"token_audience_strict", cfg.tokenAudienceStrict,
		"github_refresh_enabled", cfg.githubRefreshEnabled,
		"auth_audit_log_path", auditRecorder.Path(),
	)

	server := &http.Server{
		Addr:              cfg.bindAddr,
		Handler:           serverMiddleware(mux, trustedProxies),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      0, // unlimited: MCP streaming responses may be long-lived
		IdleTimeout:       120 * time.Second,
	}

	// Phase B (#72) delegated-access PoC: optional loopback-only internal API.
	// Activated only when both env vars are set; missing either → disabled
	// (fail-closed) with an explicit log so misconfiguration is obvious.
	startInternalAPI(oauthHandler, oauthHandler)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

// runSetupWizard starts an HTTP server that serves only the /setup endpoint.
// It blocks until a successful POST /setup causes the process to exit (so the
// supervisor can restart in normal mode), or until the listener fails.
func runSetupWizard(cfg config, appCfg *appconfig.AppConfig, km *appconfig.KeyMaterial, envClientID, envSecret string, hasEnvRoutes bool, trustedProxies []netip.Prefix) {
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
		Handler:           serverMiddleware(mux, trustedProxies),
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

func serverMiddleware(h http.Handler, trustedProxies []netip.Prefix) http.Handler {
	return middleware.ProxyHeaders(trustedProxies)(middleware.Logger()(h))
}

type config struct {
	githubClientID     string
	githubClientSecret string
	// publicURL is the canonical base URL visible to OAuth / MCP clients.
	// Replaces the deprecated baseURL / MCP_GATEWAY_BASE_URL.
	publicURL string
	// bindAddr is the TCP address the HTTP listener binds to (host:port).
	bindAddr             string
	oauthProvider        string
	oauthScopes          string
	oidcIssuerURL        string
	oidcAudience         string
	port                 string
	logLevel             string
	upstreamURL          string // deprecated; prefer ROUTE_* env vars
	trustedProxyCIDRs    []string
	sessionTTLMin        int
	tokenCacheTTLMin     int
	tokenExpiresInSec    int
	tokenAudienceStrict  bool
	githubRefreshEnabled bool
	tokenStorePath       string
	keyPath              string
	configPath           string
	allowedRedirectHosts   []string
	allowedRedirectSchemes []string
	// upstream OAuth state paths
	upstreamClientStorePath string
	upstreamTokenStorePath  string
}

func loadConfig() config {
	port := getEnv("MCP_GATEWAY_PORT", "8080")

	// publicURL resolution: MCP_GATEWAY_PUBLIC_URL > MCP_GATEWAY_BASE_URL > default.
	// Deprecation warning for MCP_GATEWAY_BASE_URL is emitted in main() after logger init.
	publicURL := getEnv("MCP_GATEWAY_PUBLIC_URL",
		getEnv("MCP_GATEWAY_BASE_URL", "http://127.0.0.1:"+port))

	// bindAddr defaults to loopback; Docker deployments should set MCP_GATEWAY_BIND_ADDR=0.0.0.0:<port>.
	bindAddr := getEnv("MCP_GATEWAY_BIND_ADDR", "127.0.0.1:"+port)

	// OAuth scopes: OAUTH_SCOPES > legacy GITHUB_MCP_OAUTH_SCOPES > default.
	oauthScopes := "repo,user"
	if v, ok := appconfig.ResolveOAuthEnv("OAUTH_SCOPES", "GITHUB_MCP_OAUTH_SCOPES"); ok {
		oauthScopes = v
	}

	// OAuth provider kind: defaults to "github" for backward compatibility.
	oauthProvider := getEnv("OAUTH_PROVIDER", "github")

	stateDir := gatewayStateDir()
	ensureGatewayStateDir()

	return config{
		// githubClientID and githubClientSecret are resolved after key/config loading in main().
		publicURL:            publicURL,
		bindAddr:             bindAddr,
		port:                 port,
		oauthProvider:        oauthProvider,
		oauthScopes:          oauthScopes,
		oidcIssuerURL:        getEnv("OAUTH_ISSUER_URL", ""),
		oidcAudience:         getEnv("OAUTH_AUDIENCE", ""),
		logLevel:             getEnv("LOG_LEVEL", "info"),
		upstreamURL:          getEnv("GITHUB_MCP_UPSTREAM_URL", ""),
		trustedProxyCIDRs:    splitCSV(os.Getenv("MCP_GATEWAY_TRUSTED_PROXIES")),
		sessionTTLMin:        getEnvInt("SESSION_TTL_MIN", 10),
		tokenCacheTTLMin:     getEnvInt("TOKEN_CACHE_TTL_MIN", 30),
		tokenExpiresInSec:    getEnvInt("TOKEN_EXPIRES_IN_SEC", 7776000), // 90 days
		tokenAudienceStrict:  getEnvBool("MCP_GATEWAY_TOKEN_AUDIENCE_STRICT", false),
		githubRefreshEnabled: getEnvBool("MCP_GATEWAY_GITHUB_REFRESH_ENABLED", false),
		tokenStorePath:       lookupEnv("MCP_GATEWAY_TOKEN_STORE_PATH", filepath.Join(stateDir, "tokens.json")),
		keyPath:              getEnv("MCP_GATEWAY_KEY_PATH", filepath.Join(stateDir, "gateway.key")),
		configPath:           getEnv("MCP_CONFIG_FILE", filepath.Join(stateDir, "config.yaml")),
		allowedRedirectHosts:   splitCSV(os.Getenv("MCP_GATEWAY_ALLOWED_REDIRECT_HOSTS")),
		allowedRedirectSchemes: splitCSV(os.Getenv("MCP_GATEWAY_ALLOWED_REDIRECT_SCHEMES")),
		upstreamClientStorePath: filepath.Join(stateDir, "upstream_clients.json"),
		upstreamTokenStorePath:  filepath.Join(stateDir, "upstream_tokens.json"),
	}
}

func splitCSV(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

// buildResourceAudienceMap builds the map from resource identifier → required_audience
// used by auth.Handler to resolve the resource parameter in /token requests.
//
// Three families of keys are registered:
//   - publicURL (base, no path) → "mcp-gateway" always; overridden by a "/" prefix
//     route's RequiredAudience when one is present. Covers the gateway-wide PRM
//     (/.well-known/oauth-protected-resource, no path suffix) that RFC 8707 clients
//     use to discover resource=<publicURL>.
//   - route name (e.g. "cloudflare") → route.RequiredAudience, for backward
//     compatibility with clients that send the short name as the resource.
//   - publicURL+prefix (e.g. "http://127.0.0.1:8080/mcp/cloudflare") →
//     route.RequiredAudience, for RFC 8707 clients that use the per-route PRM
//     resource value directly (#175).
func buildResourceAudienceMap(routes []router.Route, publicURL string) map[string]string {
	base := strings.TrimRight(publicURL, "/")
	m := make(map[string]string, len(routes)*2+1)
	// Pre-register the gateway-wide resource so resource=<publicURL> always resolves,
	// even when no "/" prefix route is explicitly configured.
	m[base] = "mcp-gateway"
	for _, route := range routes {
		if route.NoAuth {
			continue
		}
		m[route.Name] = route.RequiredAudience
		if route.Prefix == "/" {
			// "/" prefix: PRM resource is publicURL; override the default entry
			// with the route's actual required audience.
			m[base] = route.RequiredAudience
		} else {
			// Non-root prefix: also register the full URL form (publicURL+prefix)
			// as advertised by the per-route PRM, so RFC 8707 clients can pass
			// the PRM resource value directly as resource= (#175).
			m[base+route.Prefix] = route.RequiredAudience
		}
	}
	return m
}

// gatewayStateDir returns the OS-appropriate user-owned directory for
// mcp-gateway's runtime state files (gateway.key, config.yaml, tokens.json).
// Docker operators override these paths via environment variables; this default
// only affects bare-metal / non-containerised deployments.
//
// On Linux/other, XDG_STATE_HOME is preferred (consistent with authaudit defaults
// and the official Docker image which sets XDG_STATE_HOME=/data).
func gatewayStateDir() string {
	switch runtime.GOOS {
	case "windows":
		if base := strings.TrimSpace(os.Getenv("LOCALAPPDATA")); base != "" {
			return filepath.Join(base, "mcp-gateway")
		}
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Application Support", "mcp-gateway")
		}
	default:
		// XDG_STATE_HOME matches authaudit convention; Docker image sets XDG_STATE_HOME=/data.
		if base := strings.TrimSpace(os.Getenv("XDG_STATE_HOME")); base != "" {
			return filepath.Join(base, "mcp-gateway")
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, ".local", "state", "mcp-gateway")
		}
	}
	return filepath.Join(".", ".mcp-gateway")
}

// ensureGatewayStateDir creates the gateway state directory if it does not exist.
// LoadKey / SaveConfig / NewFileTokenStore do not create parent directories, so
// a clean install would fail on the first run without this call.
func ensureGatewayStateDir() {
	d := gatewayStateDir()
	if err := os.MkdirAll(d, 0700); err != nil {
		slog.Warn("could not create gateway state directory", "path", d, "err", err)
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

func getEnvBool(key string, fallback bool) bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if v == "" {
		return fallback
	}
	switch v {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
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

// startInternalAPI launches the Phase B (#72) delegated-access loopback API
// when MCP_GATEWAY_INTERNAL_SECRET and MCP_GATEWAY_INTERNAL_PORT are both set.
// Missing or invalid configuration fails closed: the API is simply not served
// and a log line announces the disabled state. We never bind to a non-loopback
// address.
func startInternalAPI(resolver internalapi.TokenResolver, failures internalapi.FailureReader) {
	secret := strings.TrimSpace(os.Getenv("MCP_GATEWAY_INTERNAL_SECRET"))
	portRaw := strings.TrimSpace(os.Getenv("MCP_GATEWAY_INTERNAL_PORT"))
	if secret == "" || portRaw == "" {
		slog.Info("internal delegated access API disabled", "reason", "env vars not set")
		return
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		slog.Error("internal delegated access API disabled: invalid port", "port", portRaw)
		return
	}
	handler, err := internalapi.NewHandler(resolver, secret, internalapi.WithFailureReader(failures))
	if err != nil {
		slog.Error("internal delegated access API disabled: invalid configuration", "err", err)
		return
	}
	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)
	addr := "127.0.0.1:" + portRaw
	// Bind synchronously so a port-in-use / permission error is surfaced
	// before we declare the API listening. Without this, the goroutine
	// below would fail asynchronously and operators would see no
	// difference between a healthy startup and a silently-absent
	// internal listener.
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		slog.Error("internal delegated access API disabled: bind failed", "addr", addr, "err", err)
		return
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           middleware.Logger()(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		// The handler may synchronously call the GitHub refresh
		// endpoint via EnsureFreshAccessTokenForSubject; the provider
		// HTTP client allows up to 15s for that call, so the server
		// write timeout must accommodate the worst-case rotation plus
		// a small buffer for response encoding.
		WriteTimeout: 20 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	slog.Info("internal delegated access API listening", "addr", addr)
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			slog.Error("internal delegated access API exited", "err", err)
		}
	}()
}
