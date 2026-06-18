package router

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
)

// DefaultRequiredAudience is the aud claim value used when a route does not
// specify required_audience. It matches the default resource for clients that
// do not pass a resource parameter to /token.
const DefaultRequiredAudience = "mcp-gateway"

// Route maps a URL path prefix to an upstream MCP server.
type Route struct {
	Name     string
	Prefix   string
	Upstream *url.URL
	NoAuth   bool // true when auth=none; skips OAuth middleware
	// UpstreamBearerTokenEnv names an env var whose trimmed value is injected as
	// the upstream Authorization Bearer token on every proxied request.
	// When empty (default), the client OAuth context token is used instead.
	// The env var must be set and non-blank at startup (fail-closed).
	// Note: the fail-closed guarantee is startup-only. If the env var is
	// cleared or rotated to empty after the gateway starts, the proxy logs a
	// warning and forwards requests without an Authorization header rather
	// than terminating. Operators must restart the gateway after rotating
	// this credential to restore fail-closed protection.
	UpstreamBearerTokenEnv string
	// RequiredAudience is the aud claim value that access tokens must carry to
	// access this route. Clients request a token with this audience by passing
	// resource=<route-name> to the /token endpoint. Defaults to "mcp-gateway".
	RequiredAudience string
	// UpstreamOAuth is "auto" or an absolute issuer URL (http/https) for upstream
	// OAuth delegation. Empty means disabled. Discovery and token exchange are
	// handled by subsequent issues; this field is parsed and validated only.
	UpstreamOAuth string
	// UpstreamOAuthScope is the space-separated OAuth scope string requested from
	// the upstream authorization server.
	UpstreamOAuthScope string
}

// ParseEnv reads ROUTE_<NAME>=<prefix>|<upstream_url>[|opt=val...] environment
// variables and returns routes sorted by prefix length (longest first).
func ParseEnv() ([]Route, error) {
	return parseRoutes(os.Environ())
}

func parseRoutes(env []string) ([]Route, error) {
	var routes []Route
	seen := make(map[string]struct{})
	for _, entry := range env {
		key, val, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(key, "ROUTE_") {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(key, "ROUTE_"))
		if name == "" {
			return nil, fmt.Errorf("%s: route name must not be empty (use ROUTE_<NAME>=...)", key)
		}
		// Skip empty values: supports docker-compose conditional patterns like
		// ${TOKEN:+route_definition} where an absent token yields an empty string.
		if strings.TrimSpace(val) == "" {
			continue
		}
		prefix, rest, found := strings.Cut(val, "|")
		if !found {
			return nil, fmt.Errorf("%s: expected <prefix>|<upstream_url>, got %q", key, val)
		}
		// Split rest into [upstreamURL, option1, option2, ...].
		parts := strings.Split(rest, "|")
		upstreamRaw := parts[0]
		optionParts := parts[1:]

		// Parse key=value options; unknown or duplicate keys are fatal (fail-closed).
		options := make(map[string]string, len(optionParts))
		for _, opt := range optionParts {
			k, v, hasVal := strings.Cut(opt, "=")
			if !hasVal {
				return nil, fmt.Errorf("%s: option %q must be in key=value format", key, opt)
			}
			if _, dup := options[k]; dup {
				return nil, fmt.Errorf("%s: duplicate option key %q", key, k)
			}
			options[k] = v
		}

		// auth option: controls client → gateway authentication.
		var noAuth bool
		if authVal, ok := options["auth"]; ok {
			switch authVal {
			case "none":
				noAuth = true
			case "oauth":
				noAuth = false
			default:
				return nil, fmt.Errorf("%s: unknown auth value %q (use auth=none or auth=oauth)", key, authVal)
			}
			delete(options, "auth")
		}

		// upstream_bearer_token_env: gateway → upstream Bearer token sourced from env.
		// The named env var must be set and non-blank at startup; fail-closed otherwise.
		// After startup, if the env var is cleared or emptied, the proxy logs a
		// warning per request and forwards without Authorization (see proxy.NewHandler).
		var upstreamBearerTokenEnv string
		if envName, ok := options["upstream_bearer_token_env"]; ok {
			envName = strings.TrimSpace(envName)
			if envName == "" {
				return nil, fmt.Errorf("%s: upstream_bearer_token_env value must not be empty", key)
			}
			if strings.TrimSpace(os.Getenv(envName)) == "" {
				return nil, fmt.Errorf("%s: upstream_bearer_token_env=%s is not set or empty (fail-closed)", key, envName)
			}
			upstreamBearerTokenEnv = envName
			delete(options, "upstream_bearer_token_env")
		}

		// required_audience: the aud claim value access tokens must carry to reach this route.
		requiredAudience := DefaultRequiredAudience
		if aud, ok := options["required_audience"]; ok {
			aud = strings.TrimSpace(aud)
			if aud == "" {
				return nil, fmt.Errorf("%s: required_audience value must not be empty", key)
			}
			requiredAudience = aud
			delete(options, "required_audience")
		}

		// upstream_oauth: enables upstream OAuth delegation.
		// Value must be "auto" or an absolute http/https issuer URL.
		// Mutually exclusive with upstream_bearer_token_env (fail-closed).
		var upstreamOAuth string
		if oauthVal, ok := options["upstream_oauth"]; ok {
			oauthVal = strings.TrimSpace(oauthVal)
			if oauthVal == "" {
				return nil, fmt.Errorf("%s: upstream_oauth value must not be empty", key)
			}
			if upstreamBearerTokenEnv != "" {
				return nil, fmt.Errorf("%s: upstream_oauth and upstream_bearer_token_env are mutually exclusive", key)
			}
			if oauthVal != "auto" {
				u, err := url.Parse(oauthVal)
				if err != nil || u.Scheme == "" || u.Host == "" {
					return nil, fmt.Errorf("%s: upstream_oauth must be \"auto\" or an absolute http/https URL (got %q)", key, oauthVal)
				}
				if u.Scheme != "http" && u.Scheme != "https" {
					return nil, fmt.Errorf("%s: upstream_oauth URL scheme must be http or https (got %q)", key, u.Scheme)
				}
				oauthVal = strings.TrimRight(oauthVal, "/")
			}
			upstreamOAuth = oauthVal
			delete(options, "upstream_oauth")
		}

		// upstream_oauth_scope: space-separated OAuth scope string.
		// Comma-separated values are normalised to space-separated.
		// upstream_oauth must be set when upstream_oauth_scope is specified.
		var upstreamOAuthScope string
		if scopeVal, ok := options["upstream_oauth_scope"]; ok {
			if upstreamOAuth == "" {
				return nil, fmt.Errorf("%s: upstream_oauth_scope requires upstream_oauth to be set", key)
			}
			scopeVal = strings.TrimSpace(scopeVal)
			if scopeVal == "" {
				return nil, fmt.Errorf("%s: upstream_oauth_scope value must not be empty or whitespace-only", key)
			}
			// Normalise comma-separated to space-separated.
			scopeVal = strings.ReplaceAll(scopeVal, ",", " ")
			// Collapse multiple spaces.
			fields := strings.Fields(scopeVal)
			upstreamOAuthScope = strings.Join(fields, " ")
			delete(options, "upstream_oauth_scope")
		}

		// Reject any unrecognised option keys.
		if len(options) > 0 {
			unknown := make([]string, 0, len(options))
			for k := range options {
				unknown = append(unknown, k)
			}
			sort.Strings(unknown)
			return nil, fmt.Errorf("%s: unknown route option(s): %s", key, strings.Join(unknown, ", "))
		}

		// Strip trailing slash(es) only when it won't erase the root prefix.
		if prefix != "/" {
			prefix = strings.TrimRight(prefix, "/")
		}
		if prefix == "" {
			return nil, fmt.Errorf("%s: prefix must not be empty", key)
		}
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("%s: prefix must start with '/' (got %q)", key, prefix)
		}
		if strings.ContainsAny(prefix, " \t\n\r") {
			return nil, fmt.Errorf("%s: prefix must not contain whitespace (got %q)", key, prefix)
		}
		u, err := url.Parse(upstreamRaw)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid upstream URL: %w", key, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("%s: upstream URL must be absolute with scheme and host (got %q)", key, upstreamRaw)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("%s: upstream URL scheme must be http or https (got %q)", key, u.Scheme)
		}
		if _, dup := seen[prefix]; dup {
			return nil, fmt.Errorf("%s: duplicate prefix %q", key, prefix)
		}
		seen[prefix] = struct{}{}
		routes = append(routes, Route{
			Name:                   name,
			Prefix:                 prefix,
			Upstream:               u,
			NoAuth:                 noAuth,
			UpstreamBearerTokenEnv: upstreamBearerTokenEnv,
			RequiredAudience:       requiredAudience,
			UpstreamOAuth:          upstreamOAuth,
			UpstreamOAuthScope:     upstreamOAuthScope,
		})
	}
	// Longest prefix first for correct matching order.
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})
	return routes, nil
}

// ParseFromConfig converts persisted RouteConfig entries (from config.yaml) into
// Route values, applying the same validation rules as ParseEnv.
// env ROUTE_* variables take precedence over config.yaml routes; this function
// is only called when ParseEnv returns no routes.
func ParseFromConfig(cfgRoutes []appconfig.RouteConfig) ([]Route, error) {
	var routes []Route
	seen := make(map[string]struct{})
	seenNames := make(map[string]struct{})
	for _, r := range cfgRoutes {
		name := strings.ToLower(strings.TrimSpace(r.Name))
		if name == "" {
			return nil, fmt.Errorf("route name must not be empty")
		}
		if _, dup := seenNames[name]; dup {
			return nil, fmt.Errorf("route %q: duplicate route name", name)
		}
		seenNames[name] = struct{}{}
		prefix := r.Prefix
		if prefix != "/" {
			prefix = strings.TrimRight(prefix, "/")
		}
		if prefix == "" {
			return nil, fmt.Errorf("route %q: prefix must not be empty", name)
		}
		if !strings.HasPrefix(prefix, "/") {
			return nil, fmt.Errorf("route %q: prefix must start with '/' (got %q)", name, prefix)
		}
		if strings.ContainsAny(prefix, " \t\n\r") {
			return nil, fmt.Errorf("route %q: prefix must not contain whitespace (got %q)", name, prefix)
		}
		u, err := url.Parse(r.Upstream)
		if err != nil {
			return nil, fmt.Errorf("route %q: invalid upstream URL: %w", name, err)
		}
		if u.Scheme == "" || u.Host == "" {
			return nil, fmt.Errorf("route %q: upstream URL must be absolute with scheme and host (got %q)", name, r.Upstream)
		}
		if u.Scheme != "http" && u.Scheme != "https" {
			return nil, fmt.Errorf("route %q: upstream URL scheme must be http or https (got %q)", name, u.Scheme)
		}
		if _, dup := seen[prefix]; dup {
			return nil, fmt.Errorf("route %q: duplicate prefix %q", name, prefix)
		}
		// upstream_bearer_token_env: apply same fail-closed validation as parseRoutes.
		upstreamBearerTokenEnv := strings.TrimSpace(r.UpstreamBearerTokenEnv)
		if r.UpstreamBearerTokenEnv != "" {
			if upstreamBearerTokenEnv == "" {
				return nil, fmt.Errorf("route %q: upstream_bearer_token_env value must not be empty", name)
			}
			if strings.TrimSpace(os.Getenv(upstreamBearerTokenEnv)) == "" {
				return nil, fmt.Errorf("route %q: upstream_bearer_token_env=%s is not set or empty (fail-closed)", name, upstreamBearerTokenEnv)
			}
		}
		requiredAudience := strings.TrimSpace(r.RequiredAudience)
		if requiredAudience == "" {
			requiredAudience = DefaultRequiredAudience
		}
		// upstream_oauth: same validation as parseRoutes.
		upstreamOAuth := strings.TrimSpace(r.UpstreamOAuth)
		if r.UpstreamOAuth != "" {
			if upstreamOAuth == "" {
				return nil, fmt.Errorf("route %q: upstream_oauth value must not be empty", name)
			}
			if upstreamBearerTokenEnv != "" {
				return nil, fmt.Errorf("route %q: upstream_oauth and upstream_bearer_token_env are mutually exclusive", name)
			}
			if upstreamOAuth != "auto" {
				pu, err := url.Parse(upstreamOAuth)
				if err != nil || pu.Scheme == "" || pu.Host == "" {
					return nil, fmt.Errorf("route %q: upstream_oauth must be \"auto\" or an absolute http/https URL (got %q)", name, upstreamOAuth)
				}
				if pu.Scheme != "http" && pu.Scheme != "https" {
					return nil, fmt.Errorf("route %q: upstream_oauth URL scheme must be http or https (got %q)", name, pu.Scheme)
				}
				upstreamOAuth = strings.TrimRight(upstreamOAuth, "/")
			}
		}
		// upstream_oauth_scope: normalise comma-separated to space-separated.
		// upstream_oauth must be set when upstream_oauth_scope is specified.
		upstreamOAuthScope := strings.TrimSpace(r.UpstreamOAuthScope)
		if r.UpstreamOAuthScope != "" {
			if upstreamOAuth == "" {
				return nil, fmt.Errorf("route %q: upstream_oauth_scope requires upstream_oauth to be set", name)
			}
			if upstreamOAuthScope == "" {
				return nil, fmt.Errorf("route %q: upstream_oauth_scope value must not be empty or whitespace-only", name)
			}
			upstreamOAuthScope = strings.ReplaceAll(upstreamOAuthScope, ",", " ")
			upstreamOAuthScope = strings.Join(strings.Fields(upstreamOAuthScope), " ")
		}
		seen[prefix] = struct{}{}
		routes = append(routes, Route{
			Name:                   name,
			Prefix:                 prefix,
			Upstream:               u,
			NoAuth:                 r.NoAuth,
			UpstreamBearerTokenEnv: upstreamBearerTokenEnv,
			RequiredAudience:       requiredAudience,
			UpstreamOAuth:          upstreamOAuth,
			UpstreamOAuthScope:     upstreamOAuthScope,
		})
	}
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})
	return routes, nil
}
