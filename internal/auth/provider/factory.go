package provider

import (
	"fmt"
	"net/url"
)

// Config carries the provider-agnostic configuration consumed by New.
// Provider-specific fields are added as additional providers are introduced.
type Config struct {
	// Kind selects the provider implementation: "github".
	Kind string

	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string
}

// New instantiates the Provider implementation selected by cfg.Kind.
func New(cfg Config) (Provider, error) {
	switch cfg.Kind {
	case "github", "":
		if cfg.ClientID == "" || cfg.ClientSecret == "" {
			return nil, fmt.Errorf("github provider requires ClientID and ClientSecret")
		}
		if cfg.RedirectURI == "" {
			return nil, fmt.Errorf("github provider requires RedirectURI")
		}
		u, err := url.Parse(cfg.RedirectURI)
		if err != nil || !u.IsAbs() || u.Host == "" || u.Fragment != "" || (u.Scheme != "http" && u.Scheme != "https") {
			return nil, fmt.Errorf("github provider requires an absolute http/https RedirectURI with a host and no fragment, got %q", cfg.RedirectURI)
		}
		return NewGitHub(GitHubConfig{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURI:  cfg.RedirectURI,
			Scopes:       cfg.Scopes,
		}), nil
	default:
		return nil, fmt.Errorf("unsupported OAuth provider %q", cfg.Kind)
	}
}
