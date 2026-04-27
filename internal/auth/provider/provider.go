// Package provider abstracts OAuth 2.0 provider-specific operations
// (authorization endpoint, token exchange, token validation) so that the
// gateway can be wired to GitHub, fly.io, OIDC, etc. via configuration.
package provider

import "context"

// Provider abstracts OAuth 2.0 provider-specific operations.
//
// Implementations hold their own client credentials and fixed URLs internally;
// callers do not pass them per request.
type Provider interface {
	// Name returns the provider identifier (e.g. "github").
	Name() string

	// ClientID returns the OAuth client identifier configured for this provider.
	// Used by the pseudo dynamic client registration endpoint (RFC 7591).
	ClientID() string

	// AuthorizeURL builds the redirect URL to the provider's authorization
	// endpoint. The state and (optional) PKCE code_challenge are forwarded.
	AuthorizeURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code for an access token.
	// scopes is the granted scope list as reported by the provider; the
	// concrete delimiter (comma / space) is normalized by the implementation.
	ExchangeCode(ctx context.Context, code string) (token string, scopes []string, err error)

	// ValidateToken validates a bearer token and returns the authenticated
	// identity. Implementations should return UpstreamError for transient
	// network/5xx failures so callers can distinguish them from auth failures.
	ValidateToken(ctx context.Context, token string) (Identity, error)
}

// Identity represents the authenticated user across providers.
//
// Subject is the unique identifier used by the gateway (GitHub: login,
// fly.io: user ID, OIDC: sub claim). DisplayName is optional and may be
// surfaced to upstream services for human-readable logging.
type Identity struct {
	Provider    string
	Subject     string
	DisplayName string
}
