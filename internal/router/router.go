package router

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// Route maps a URL path prefix to an upstream MCP server.
type Route struct {
	Name     string
	Prefix   string
	Upstream *url.URL
}

// ParseEnv reads ROUTE_<NAME>=<prefix>|<upstream_url> environment variables
// and returns routes sorted by prefix length (longest first) for correct matching.
func ParseEnv() ([]Route, error) {
	return parseRoutes(os.Environ())
}

func parseRoutes(env []string) ([]Route, error) {
	var routes []Route
	for _, entry := range env {
		key, val, found := strings.Cut(entry, "=")
		if !found || !strings.HasPrefix(key, "ROUTE_") {
			continue
		}
		name := strings.ToLower(strings.TrimPrefix(key, "ROUTE_"))
		prefix, upstreamRaw, found := strings.Cut(val, "|")
		if !found {
			return nil, fmt.Errorf("%s: expected <prefix>|<upstream_url>, got %q", key, val)
		}
		prefix = strings.TrimRight(prefix, "/")
		if prefix == "" {
			return nil, fmt.Errorf("%s: prefix must not be empty", key)
		}
		u, err := url.Parse(upstreamRaw)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid upstream URL: %w", key, err)
		}
		routes = append(routes, Route{Name: name, Prefix: prefix, Upstream: u})
	}
	// Longest prefix first for correct matching order.
	sort.Slice(routes, func(i, j int) bool {
		return len(routes[i].Prefix) > len(routes[j].Prefix)
	})
	return routes, nil
}
