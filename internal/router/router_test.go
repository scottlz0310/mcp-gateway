package router

import (
	"testing"
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
