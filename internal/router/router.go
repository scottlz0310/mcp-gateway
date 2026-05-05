package router

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
)

// Route maps a URL path prefix to an upstream MCP server.
type Route struct {
	Name     string
	Prefix   string
	Upstream *url.URL
	NoAuth   bool // true when auth=none is specified; skips OAuth middleware
}

// ParseEnv reads ROUTE_<NAME>=<prefix>|<upstream_url> environment variables
// and returns routes sorted by prefix length (longest first) for correct matching.
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
		prefix, rest, found := strings.Cut(val, "|")
		if !found {
			return nil, fmt.Errorf("%s: expected <prefix>|<upstream_url>, got %q", key, val)
		}
		upstreamRaw, authOpt, hasAuthOpt := strings.Cut(rest, "|")
		var noAuth bool
		if hasAuthOpt {
			switch authOpt {
			case "auth=none":
				noAuth = true
			case "auth=oauth":
				noAuth = false
			default:
				return nil, fmt.Errorf("%s: unknown auth option %q (use auth=none or auth=oauth)", key, authOpt)
			}
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
		routes = append(routes, Route{Name: name, Prefix: prefix, Upstream: u, NoAuth: noAuth})
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
	for _, r := range cfgRoutes {
		name := strings.ToLower(strings.TrimSpace(r.Name))
		if name == "" {
			return nil, fmt.Errorf("route name must not be empty")
		}
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
		seen[prefix] = struct{}{}
		routes = append(routes, Route{Name: name, Prefix: prefix, Upstream: u, NoAuth: r.NoAuth})
	}
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})
	return routes, nil
}
