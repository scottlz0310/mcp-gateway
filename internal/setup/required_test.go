package setup_test

import (
	"testing"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/router"
	"github.com/scottlz0310/mcp-gateway/internal/setup"
)

func mustParseEnvRoute(t *testing.T) []router.Route {
	t.Helper()
	t.Setenv("ROUTE_TEST", "/mcp|http://upstream:8080")
	routes, err := router.ParseEnv()
	if err != nil {
		t.Fatalf("ParseEnv: %v", err)
	}
	return routes
}

func TestIsSetupRequired_AllPresent(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientID = "id"
	cfg.Auth.GitHubClientSecret = "enc-secret"
	routes := mustParseEnvRoute(t)
	if setup.IsSetupRequired(cfg, "id", "secret", routes) {
		t.Error("expected setup not required, got required")
	}
}

func TestIsSetupRequired_MissingClientID(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientSecret = "enc-secret"
	routes := mustParseEnvRoute(t)
	if !setup.IsSetupRequired(cfg, "", "", routes) {
		t.Error("expected setup required (no client_id), got not required")
	}
}

func TestIsSetupRequired_MissingSecret(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientID = "id"
	routes := mustParseEnvRoute(t)
	if !setup.IsSetupRequired(cfg, "id", "", routes) {
		t.Error("expected setup required (no secret), got not required")
	}
}

func TestIsSetupRequired_MissingRoutes(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientID = "id"
	cfg.Auth.GitHubClientSecret = "enc-secret"
	if !setup.IsSetupRequired(cfg, "id", "secret", nil) {
		t.Error("expected setup required (no routes), got not required")
	}
}

func TestIsSetupRequired_ConfigRoutesCount(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientID = "id"
	cfg.Auth.GitHubClientSecret = "enc-secret"
	cfg.Routes = []appconfig.RouteConfig{{Name: "test", Prefix: "/mcp", Upstream: "http://up:8080"}}
	if setup.IsSetupRequired(cfg, "id", "secret", nil) {
		t.Error("expected setup not required (routes in config), got required")
	}
}

func TestIsSetupRequired_EnvIDWithConfigSecret(t *testing.T) {
	cfg := &appconfig.AppConfig{}
	cfg.Auth.GitHubClientSecret = "enc-secret"
	routes := mustParseEnvRoute(t)
	if setup.IsSetupRequired(cfg, "env-id", "", routes) {
		t.Error("expected setup not required (env id + config secret + env routes)")
	}
}
