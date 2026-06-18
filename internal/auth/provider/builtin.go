package provider

import (
	"context"
)

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

// ValidateToken resolves the caller's identity from the GitHub API using the
// GitHub access token obtained via ExchangeCode. This is called during the
// OAuth callback and device callback flows to populate the Subject claim.
//
// Note: in builtin mode, handler.ValidateToken (proxy-auth path) bypasses this
// method and validates gateway-issued JWTs directly via verifyGatewayJWT.
func (p *builtinProvider) ValidateToken(ctx context.Context, token string) (Identity, error) {
	return p.github.ValidateToken(ctx, token)
}
