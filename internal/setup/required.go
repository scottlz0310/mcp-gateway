package setup

import (
	"strings"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/router"
)

// IsSetupRequired returns true when any of the three effective inputs —
// client_id, client_secret, or routes — is missing from the combined
// env + config.yaml sources.
//
// The check is intentionally independent of setup.completed: even if the
// flag is true, missing effective config still triggers the wizard to
// guard against inconsistent state.
func IsSetupRequired(appCfg *appconfig.AppConfig, envClientID, envSecret string, envRoutes []router.Route) bool {
	hasClientID := strings.TrimSpace(envClientID) != "" || strings.TrimSpace(appCfg.Auth.GitHubClientID) != ""
	hasSecret := strings.TrimSpace(appCfg.Auth.GitHubClientSecret) != "" || strings.TrimSpace(envSecret) != ""
	hasRoutes := len(envRoutes) > 0 || len(appCfg.Routes) > 0
	return !hasClientID || !hasSecret || !hasRoutes
}
