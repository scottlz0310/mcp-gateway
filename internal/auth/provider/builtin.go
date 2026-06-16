package provider

import (
	"context"
	"errors"
)

// ErrBuiltinValidateNotSupported is returned when ValidateToken is called on the
// builtin provider. In builtin mode, gateway-issued JWTs are validated directly
// by the handler (which holds the RSA signing key), not via the upstream provider.
var ErrBuiltinValidateNotSupported = errors.New("builtin provider: ValidateToken must be handled by the gateway JWT verifier")

// builtinProvider wraps the GitHub OAuth flow so that the gateway can use
// GitHub as a social login source while issuing its own RS256 JWTs as
// access tokens. The handler detects Name() == "builtin" and switches to
// gateway-issued token logic instead of forwarding GitHub tokens to clients.
type builtinProvider struct {
	github Provider
}

// NewBuiltin returns a Provider backed by GitHub OAuth for identity resolution.
// The handler must check Name() == "builtin" and apply gateway-JWT issuance
// instead of using the GitHub access token as the client-facing access token.
func NewBuiltin(githubCfg GitHubConfig) Provider {
	return &builtinProvider{github: NewGitHub(githubCfg)}
}

func (p *builtinProvider) Name() string     { return "builtin" }
func (p *builtinProvider) ClientID() string { return p.github.ClientID() }
func (p *builtinProvider) Scopes() string   { return p.github.Scopes() }

// AuthorizeURL builds a GitHub OAuth authorization URL for social login.
// PKCE code_challenge is forwarded to preserve the PKCE binding between the
// MCP client and this gateway (GitHub classic OAuth ignores it server-side,
// but the gateway enforces it in tokenAuthCode).
func (p *builtinProvider) AuthorizeURL(state, codeChallenge string) string {
	return p.github.AuthorizeURL(state, codeChallenge)
}

// ExchangeCode exchanges an authorization code for a GitHub access token.
// The returned TokenResponse.AccessToken is the GitHub access token, which
// the handler uses solely to resolve identity (GET /user). The handler
// discards it and issues a gateway-signed JWT to the client instead.
func (p *builtinProvider) ExchangeCode(ctx context.Context, code string) (TokenResponse, error) {
	return p.github.ExchangeCode(ctx, code)
}

// RefreshToken is not used in builtin mode. Gateway refresh token rotation is
// managed entirely by the handler; GitHub refresh tokens are never persisted.
func (p *builtinProvider) RefreshToken(_ context.Context, _ string) (TokenResponse, error) {
	return TokenResponse{}, ErrRefreshNotSupported
}

// ValidateToken must not be called in builtin mode. The handler validates
// gateway-issued JWTs directly using its RSA private key.
func (p *builtinProvider) ValidateToken(_ context.Context, _ string) (Identity, error) {
	return Identity{}, ErrBuiltinValidateNotSupported
}
