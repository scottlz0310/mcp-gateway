package router

import (
	"testing"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
)

func TestParseRoutesEmpty(t *testing.T) {
	routes, err := parseRoutes(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestParseRoutesSingle(t *testing.T) {
	env := []string{"ROUTE_GITHUB=/mcp/github|http://github-mcp:8082"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].Name != "github" {
		t.Errorf("name: got %q, want %q", routes[0].Name, "github")
	}
	if routes[0].Prefix != "/mcp/github" {
		t.Errorf("prefix: got %q, want %q", routes[0].Prefix, "/mcp/github")
	}
	if routes[0].Upstream.String() != "http://github-mcp:8082" {
		t.Errorf("upstream: got %q, want %q", routes[0].Upstream.String(), "http://github-mcp:8082")
	}
}

func TestParseRoutesSortedLongestFirst(t *testing.T) {
	env := []string{
		"ROUTE_A=/mcp|http://a:8080",
		"ROUTE_B=/mcp/copilot|http://b:8081",
		"ROUTE_C=/mcp/copilot/review|http://c:8082",
	}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 3 {
		t.Fatalf("expected 3 routes, got %d", len(routes))
	}
	if routes[0].Prefix != "/mcp/copilot/review" {
		t.Errorf("first (longest) prefix: got %q", routes[0].Prefix)
	}
	if routes[2].Prefix != "/mcp" {
		t.Errorf("last (shortest) prefix: got %q", routes[2].Prefix)
	}
}

func TestParseRoutesTrailingSlashStripped(t *testing.T) {
	env := []string{"ROUTE_X=/mcp/|http://x:8080"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if routes[0].Prefix != "/mcp" {
		t.Errorf("trailing slash not stripped: got %q", routes[0].Prefix)
	}
}

func TestParseRoutesNonRouteVarsIgnored(t *testing.T) {
	env := []string{
		"HOME=/root",
		"PATH=/usr/bin",
		"ROUTE_A=/mcp|http://a:8080",
	}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Errorf("expected 1 route, got %d", len(routes))
	}
}

func TestParseRoutesRootPrefix(t *testing.T) {
	env := []string{"ROUTE_ROOT=/|http://root:8080"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error for root prefix: %v", err)
	}
	if routes[0].Prefix != "/" {
		t.Errorf("root prefix: got %q, want %q", routes[0].Prefix, "/")
	}
}

func TestParseRoutesEmptyName(t *testing.T) {
	env := []string{"ROUTE_=/mcp|http://x:8080"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for empty route name")
	}
}

func TestParseRoutesInvalidFormat(t *testing.T) {
	env := []string{"ROUTE_BAD=nopipe"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for missing pipe separator")
	}
}

func TestParseRoutesEmptyPrefix(t *testing.T) {
	env := []string{"ROUTE_BAD=|http://x:8080"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for empty prefix")
	}
}

func TestParseRoutesPrefixMissingLeadingSlash(t *testing.T) {
	env := []string{"ROUTE_BAD=mcp|http://x:8080"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for prefix not starting with '/'")
	}
}

func TestParseRoutesPrefixWithWhitespace(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp /foo|http://x:8080"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for prefix containing whitespace")
	}
}

func TestParseRoutesOpaqueUpstreamURL(t *testing.T) {
	// url.Parse accepts "github-mcp:8082" as scheme=github-mcp, opaque=8082, host=""
	// ReverseProxy requires absolute URL with host; this must be rejected.
	env := []string{"ROUTE_BAD=/mcp|github-mcp:8082"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for opaque/relative upstream URL")
	}
}

func TestParseRoutesRelativeUpstreamURL(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp|/relative/path"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for relative upstream URL")
	}
}

func TestParseRoutesNonHTTPScheme(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp|ftp://x:8080"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for non-http/https upstream scheme")
	}
}

func TestParseRoutesDuplicatePrefix(t *testing.T) {
	env := []string{
		"ROUTE_A=/mcp|http://a:8080",
		"ROUTE_B=/mcp|http://b:8081",
	}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for duplicate prefix")
	}
}

func TestParseRoutesAuthNone(t *testing.T) {
	env := []string{"ROUTE_PLAY=/mcp/playwright|http://playwright:8931|auth=none"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if !routes[0].NoAuth {
		t.Error("expected NoAuth=true for auth=none")
	}
}

func TestParseRoutesAuthOAuth(t *testing.T) {
	env := []string{"ROUTE_GH=/mcp/github|http://github-mcp:8082|auth=oauth"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].NoAuth {
		t.Error("expected NoAuth=false for auth=oauth")
	}
}

func TestParseRoutesAuthDefault(t *testing.T) {
	env := []string{"ROUTE_GH=/mcp/github|http://github-mcp:8082"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].NoAuth {
		t.Error("expected NoAuth=false when auth option is omitted")
	}
}

func TestParseRoutesAuthInvalid(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp/bad|http://bad:9000|auth=magic"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for unknown auth option")
	}
}

func TestParseRoutesMixedAuth(t *testing.T) {
	env := []string{
		"ROUTE_GH=/mcp/github|http://github-mcp:8082",
		"ROUTE_PLAY=/mcp/playwright|http://playwright:8931|auth=none",
	}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, r := range routes {
		switch r.Name {
		case "gh":
			if r.NoAuth {
				t.Errorf("github route should require auth")
			}
		case "play":
			if !r.NoAuth {
				t.Errorf("playwright route should skip auth")
			}
		}
	}
}

func TestParseFromConfig_Valid(t *testing.T) {
	cfgRoutes := []appconfig.RouteConfig{
		{Name: "mcp", Prefix: "/mcp", Upstream: "http://upstream:8080"},
		{Name: "play", Prefix: "/play", Upstream: "http://playwright:8931", NoAuth: true},
	}
	routes, err := ParseFromConfig(cfgRoutes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 2 {
		t.Fatalf("expected 2 routes, got %d", len(routes))
	}
	for _, r := range routes {
		if r.Name == "play" && !r.NoAuth {
			t.Error("play route: expected NoAuth=true")
		}
		if r.Name == "mcp" && r.NoAuth {
			t.Error("mcp route: expected NoAuth=false")
		}
	}
}

func TestParseFromConfig_Empty(t *testing.T) {
	routes, err := ParseFromConfig(nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 0 {
		t.Errorf("expected 0 routes, got %d", len(routes))
	}
}

func TestParseFromConfig_DuplicatePrefix(t *testing.T) {
	cfgRoutes := []appconfig.RouteConfig{
		{Name: "a", Prefix: "/mcp", Upstream: "http://a:8080"},
		{Name: "b", Prefix: "/mcp", Upstream: "http://b:8081"},
	}
	_, err := ParseFromConfig(cfgRoutes)
	if err == nil {
		t.Fatal("expected error for duplicate prefix")
	}
}

func TestParseFromConfig_InvalidUpstream(t *testing.T) {
	cfgRoutes := []appconfig.RouteConfig{
		{Name: "bad", Prefix: "/mcp", Upstream: "ftp://x:8080"},
	}
	_, err := ParseFromConfig(cfgRoutes)
	if err == nil {
		t.Fatal("expected error for non-http upstream")
	}
}

func TestParseFromConfig_SortedLongestFirst(t *testing.T) {
	cfgRoutes := []appconfig.RouteConfig{
		{Name: "short", Prefix: "/mcp", Upstream: "http://a:8080"},
		{Name: "long", Prefix: "/mcp/github", Upstream: "http://b:8081"},
	}
	routes, err := ParseFromConfig(cfgRoutes)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if routes[0].Prefix != "/mcp/github" {
		t.Errorf("first route should be longest prefix, got %q", routes[0].Prefix)
	}
}

// Tests for multi-option ROUTE_* parser (upstream_bearer_token_env, duplicates, unknowns)

func TestParseRoutesUpstreamBearerTokenEnv(t *testing.T) {
	t.Setenv("CLOUDFLARE_API_TOKEN", "test-cf-token")
	env := []string{"ROUTE_CF=/mcp/cloudflare|https://mcp.cloudflare.com/mcp|upstream_bearer_token_env=CLOUDFLARE_API_TOKEN"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].UpstreamBearerTokenEnv != "CLOUDFLARE_API_TOKEN" {
		t.Errorf("UpstreamBearerTokenEnv: got %q, want %q", routes[0].UpstreamBearerTokenEnv, "CLOUDFLARE_API_TOKEN")
	}
}

func TestParseRoutesUpstreamBearerTokenEnvNotSet(t *testing.T) {
	t.Setenv("CF_TOKEN_EMPTY", "")
	env := []string{"ROUTE_CF=/mcp/cloudflare|https://mcp.cloudflare.com/mcp|upstream_bearer_token_env=CF_TOKEN_EMPTY"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for empty env var (fail-closed)")
	}
}

func TestParseRoutesUpstreamBearerTokenEnvNameEmpty(t *testing.T) {
	env := []string{"ROUTE_CF=/mcp/cloudflare|https://mcp.cloudflare.com/mcp|upstream_bearer_token_env="}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for empty upstream_bearer_token_env value")
	}
}

func TestParseRoutesUnknownOption(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp/bad|http://bad:9000|foo=bar"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for unknown route option")
	}
}

func TestParseRoutesDuplicateOptionKey(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp/bad|http://bad:9000|auth=oauth|auth=none"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for duplicate option key")
	}
}

func TestParseRoutesOptionWithoutEquals(t *testing.T) {
	env := []string{"ROUTE_BAD=/mcp/bad|http://bad:9000|auth"}
	_, err := parseRoutes(env)
	if err == nil {
		t.Fatal("expected error for option without key=value format")
	}
}

func TestParseRoutesAuthOAuthWithUpstreamBearerTokenEnv(t *testing.T) {
	t.Setenv("MY_API_TOKEN", "my-secret-token")
	env := []string{"ROUTE_EXT=/mcp/ext|https://ext.example.com/mcp|auth=oauth|upstream_bearer_token_env=MY_API_TOKEN"}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route, got %d", len(routes))
	}
	if routes[0].NoAuth {
		t.Error("expected NoAuth=false for auth=oauth")
	}
	if routes[0].UpstreamBearerTokenEnv != "MY_API_TOKEN" {
		t.Errorf("UpstreamBearerTokenEnv: got %q, want %q", routes[0].UpstreamBearerTokenEnv, "MY_API_TOKEN")
	}
}

func TestParseRoutesEmptyValueSkipped(t *testing.T) {
	// Empty ROUTE_* values must be silently skipped.
	// This supports docker-compose conditional patterns like
	// ${TOKEN:+route_definition} where an absent token yields an empty string.
	env := []string{
		"ROUTE_CLOUDFLARE=",
		"ROUTE_GITHUB=/mcp/github|http://github-mcp:8082",
		"ROUTE_EMPTY=   ",
	}
	routes, err := parseRoutes(env)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(routes) != 1 {
		t.Fatalf("expected 1 route (non-empty only), got %d", len(routes))
	}
	if routes[0].Name != "github" {
		t.Errorf("expected route name %q, got %q", "github", routes[0].Name)
	}
}
