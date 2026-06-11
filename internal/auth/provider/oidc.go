package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// OIDCConfig configures the OIDC OAuth provider.
type OIDCConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string
	IssuerURL    string
	Audience     string // Optional: used if additional audience verification is needed

	// HTTPClient overrides the default 15s-timeout client. For tests.
	HTTPClient *http.Client
}

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserInfoEndpoint      string `json:"userinfo_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	Issuer                string `json:"issuer"`
}

type oidcProvider struct {
	cfg       OIDCConfig
	client    *http.Client
	discovery oidcDiscovery
}

// NewOIDC returns a Provider backed by generic OIDC (OpenID Connect).
// It queries the provider's .well-known/openid-configuration endpoint at creation time.
func NewOIDC(cfg OIDCConfig) (Provider, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("provider.NewOIDC: IssuerURL is required")
	}

	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}

	// Fetch OIDC discovery document
	issuer := strings.TrimRight(cfg.IssuerURL, "/")
	discURL := issuer + "/.well-known/openid-configuration"

	var disc oidcDiscovery
	var lastErr error
	for attempt := 1; attempt <= 3; attempt++ {
		req, err := http.NewRequest(http.MethodGet, discURL, nil)
		if err != nil {
			return nil, fmt.Errorf("provider.NewOIDC: building discovery request: %w", err)
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("discovery endpoint unreachable: %w", err)
			time.Sleep(500 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
			lastErr = fmt.Errorf("discovery returned status %d: %s", resp.StatusCode, strings.TrimSpace(string(snippet)))
			time.Sleep(500 * time.Millisecond)
			continue
		}

		if err := json.NewDecoder(resp.Body).Decode(&disc); err != nil {
			return nil, fmt.Errorf("provider.NewOIDC: decoding discovery doc: %w", err)
		}
		lastErr = nil
		break
	}

	if lastErr != nil {
		return nil, fmt.Errorf("provider.NewOIDC: failed to fetch discovery doc after 3 attempts: %w", lastErr)
	}

	if disc.AuthorizationEndpoint == "" || disc.TokenEndpoint == "" {
		return nil, fmt.Errorf("provider.NewOIDC: missing required endpoints (authorization_endpoint or token_endpoint) in discovery doc")
	}

	return &oidcProvider{
		cfg:       cfg,
		client:    client,
		discovery: disc,
	}, nil
}

func (p *oidcProvider) Name() string     { return "oidc" }
func (p *oidcProvider) ClientID() string { return p.cfg.ClientID }
func (p *oidcProvider) Scopes() string   { return p.cfg.Scopes }

func (p *oidcProvider) AuthorizeURL(state, codeChallenge string) string {
	u, err := url.Parse(p.discovery.AuthorizationEndpoint)
	if err != nil {
		// Should not happen as we parsed/validated at construction, but fallback to string concatenation if it does.
		return p.discovery.AuthorizationEndpoint
	}
	q := u.Query()
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("response_type", "code")
	q.Set("state", state)
	if p.cfg.Scopes != "" {
		q.Set("scope", p.cfg.Scopes)
	} else {
		q.Set("scope", "openid profile email")
	}
	// OIDC spec supports PKCE. Pass code_challenge if provided.
	if codeChallenge != "" {
		q.Set("code_challenge", codeChallenge)
		q.Set("code_challenge_method", "S256")
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *oidcProvider) ExchangeCode(ctx context.Context, code string) (TokenResponse, error) {
	form := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":         {code},
		"redirect_uri": {p.cfg.RedirectURI},
	}
	return p.postToken(ctx, form, "exchange")
}

func (p *oidcProvider) RefreshToken(ctx context.Context, refreshToken string) (TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenResponse{}, fmt.Errorf("RefreshToken: refresh token must not be empty")
	}
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"refresh_token": {refreshToken},
	}
	return p.postToken(ctx, form, "refresh")
}

func (p *oidcProvider) postToken(ctx context.Context, form url.Values, op string) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("building OIDC token %s request: %w", op, err)}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("OIDC token endpoint unreachable: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if resp.StatusCode >= 500 {
			return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("OIDC token %s returned %d: %s", op, resp.StatusCode, strings.TrimSpace(string(snippet)))}
		}
		return TokenResponse{}, fmt.Errorf("OIDC token %s returned %d: %s", op, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var result struct {
		AccessToken  string `json:"access_token"`
		Scope        string `json:"scope"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
		Error        string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return TokenResponse{}, fmt.Errorf("decoding OIDC token %s response: %w", op, err)
	}
	if result.Error != "" {
		return TokenResponse{}, fmt.Errorf("OIDC token %s error: %s", op, result.Error)
	}
	if result.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("empty access_token from OIDC on %s", op)
	}

	var scopes []string
	if result.Scope != "" {
		scopes = strings.Split(result.Scope, " ")
	}

	return TokenResponse{
		AccessToken:          result.AccessToken,
		Scopes:               scopes,
		RefreshToken:         result.RefreshToken,
		AccessTokenExpiresIn: time.Duration(result.ExpiresIn) * time.Second,
	}, nil
}

func (p *oidcProvider) ValidateToken(ctx context.Context, token string) (Identity, error) {
	if p.discovery.UserInfoEndpoint == "" {
		return Identity{}, fmt.Errorf("OIDC provider does not support userinfo endpoint (required for token validation)")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.discovery.UserInfoEndpoint, nil)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("building OIDC userinfo request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := p.client.Do(req)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("OIDC userinfo endpoint unreachable: %w", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return Identity{}, fmt.Errorf("invalid token: OIDC userinfo returned %d", resp.StatusCode)
		case http.StatusForbidden, http.StatusTooManyRequests:
			return Identity{}, &UpstreamError{Err: fmt.Errorf("OIDC userinfo returned %d", resp.StatusCode)}
		default:
			if resp.StatusCode >= 500 {
				return Identity{}, &UpstreamError{Err: fmt.Errorf("OIDC userinfo returned %d", resp.StatusCode)}
			}
			return Identity{}, fmt.Errorf("invalid token: OIDC userinfo returned %d", resp.StatusCode)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("reading OIDC userinfo response: %w", err)}
	}

	var user struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return Identity{}, fmt.Errorf("decoding OIDC userinfo response: %w", err)
	}

	if user.Sub == "" {
		return Identity{}, fmt.Errorf("OIDC userinfo response missing sub claim")
	}

	displayName := user.PreferredUsername
	if displayName == "" {
		displayName = user.Name
	}
	if displayName == "" {
		displayName = user.Email
	}
	if displayName == "" {
		displayName = user.Sub
	}

	return Identity{
		Provider:    "oidc",
		Subject:     user.Sub,
		DisplayName: displayName,
	}, nil
}
