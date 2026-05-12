// Package provider abstracts OAuth 2.0 provider-specific operations
// (authorization endpoint, token exchange, token validation) so that the
// gateway can be wired to GitHub, fly.io, OIDC, etc. via configuration.
package provider

import (
	"context"
	"errors"
	"time"
)

// ErrRefreshNotSupported is returned by Provider.RefreshToken when the
// implementation does not support refresh-token rotation (e.g. GitHub OAuth
// Apps with expiring tokens disabled).
var ErrRefreshNotSupported = errors.New("provider does not support refresh tokens")

// TokenResponse is the normalized result of an OAuth token endpoint call.
//
// AccessTokenExpiresIn and RefreshTokenExpiresIn carry the provider-advertised
// lifetime when available; a zero value means the provider did not return that
// hint and the caller should fall back to its own default policy.
type TokenResponse struct {
	AccessToken           string
	Scopes                []string
	RefreshToken          string
	AccessTokenExpiresIn  time.Duration
	RefreshTokenExpiresIn time.Duration
}

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

	// Scopes returns the comma-separated OAuth scopes configured for this provider.
	// Used by Device Authorization Grant to enforce least-privilege scope.
	Scopes() string

	// AuthorizeURL builds the redirect URL to the provider's authorization
	// endpoint. The state and (optional) PKCE code_challenge are forwarded.
	AuthorizeURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code for tokens. The returned
	// TokenResponse carries the access token, granted scopes, and (when the
	// provider advertises them) a refresh token and expiry hints.
	ExchangeCode(ctx context.Context, code string) (TokenResponse, error)

	// RefreshToken rotates a provider-issued refresh token, returning a fresh
	// access token (and typically a new refresh token).  Implementations that
	// do not support refresh return ErrRefreshNotSupported so callers can
	// distinguish "not supported" from transient upstream failures.
	RefreshToken(ctx context.Context, refreshToken string) (TokenResponse, error)

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
