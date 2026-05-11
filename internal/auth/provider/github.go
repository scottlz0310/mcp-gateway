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

const (
	githubAuthorizeURL = "https://github.com/login/oauth/authorize"
	githubTokenURL     = "https://github.com/login/oauth/access_token"
	githubUserAPI      = "https://api.github.com/user"
)

// GitHubConfig configures the GitHub OAuth provider.
type GitHubConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       string

	// AuthorizeURL / TokenURL / UserAPI are exposed for testing. When zero,
	// the public github.com endpoints are used.
	AuthorizeURL string
	TokenURL     string
	UserAPI      string

	// HTTPClient overrides the default 15s-timeout client. For tests.
	HTTPClient *http.Client
}

type githubProvider struct {
	cfg          GitHubConfig
	client       *http.Client
	authorizeURL *url.URL // pre-parsed at construction to catch misconfigurations early
}

// NewGitHub returns a Provider backed by GitHub OAuth 2.0.
// It panics if AuthorizeURL is not a valid URL, to catch misconfigurations at startup.
func NewGitHub(cfg GitHubConfig) Provider {
	if cfg.AuthorizeURL == "" {
		cfg.AuthorizeURL = githubAuthorizeURL
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = githubTokenURL
	}
	if cfg.UserAPI == "" {
		cfg.UserAPI = githubUserAPI
	}
	authorizeURL, err := url.Parse(cfg.AuthorizeURL)
	if err != nil {
		panic(fmt.Sprintf("provider.NewGitHub: invalid AuthorizeURL %q: %v", cfg.AuthorizeURL, err))
	}
	if !authorizeURL.IsAbs() || (authorizeURL.Scheme != "http" && authorizeURL.Scheme != "https") {
		panic(fmt.Sprintf("provider.NewGitHub: AuthorizeURL %q must be an absolute http/https URL", cfg.AuthorizeURL))
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &githubProvider{cfg: cfg, client: client, authorizeURL: authorizeURL}
}

func (p *githubProvider) Name() string     { return "github" }
func (p *githubProvider) ClientID() string { return p.cfg.ClientID }
func (p *githubProvider) Scopes() string   { return p.cfg.Scopes }

func (p *githubProvider) AuthorizeURL(state, codeChallenge string) string {
	u := *p.authorizeURL // shallow copy to avoid mutating the stored URL
	q := u.Query()
	q.Set("client_id", p.cfg.ClientID)
	q.Set("redirect_uri", p.cfg.RedirectURI)
	q.Set("state", state)
	q.Set("scope", p.cfg.Scopes)
	// GitHub classic OAuth does not consume code_challenge; PKCE is enforced
	// between the MCP client and this gateway in handler.Token, not upstream.
	_ = codeChallenge
	u.RawQuery = q.Encode()
	return u.String()
}

func (p *githubProvider) ExchangeCode(ctx context.Context, code string) (TokenResponse, error) {
	form := url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURI},
	}
	return p.postToken(ctx, form, "exchange")
}

// RefreshToken rotates a GitHub OAuth refresh token (RFC 6749 §6).  Only
// works when the OAuth App is configured with expiring user access tokens;
// otherwise GitHub returns an OAuth error which is surfaced verbatim.
func (p *githubProvider) RefreshToken(ctx context.Context, refreshToken string) (TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return TokenResponse{}, fmt.Errorf("RefreshToken: refresh token must not be empty")
	}
	form := url.Values{
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
	}
	return p.postToken(ctx, form, "refresh")
}

// postToken issues a request to GitHub's token endpoint and decodes the
// normalized OAuth response shared by exchange and refresh flows.
func (p *githubProvider) postToken(ctx context.Context, form url.Values, op string) (TokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		p.cfg.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("building GitHub token %s request: %w", op, err)}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.client.Do(req)
	if err != nil {
		return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("GitHub token endpoint unreachable: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if resp.StatusCode >= 500 {
			return TokenResponse{}, &UpstreamError{Err: fmt.Errorf("GitHub OAuth %s returned %d: %s", op, resp.StatusCode, strings.TrimSpace(string(snippet)))}
		}
		return TokenResponse{}, fmt.Errorf("GitHub OAuth %s returned %d: %s", op, resp.StatusCode, strings.TrimSpace(string(snippet)))
	}

	var result struct {
		AccessToken           string `json:"access_token"`
		Scope                 string `json:"scope"`
		RefreshToken          string `json:"refresh_token"`
		ExpiresIn             int64  `json:"expires_in"`
		RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
		Error                 string `json:"error"`
		ErrorDescription      string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return TokenResponse{}, fmt.Errorf("decoding GitHub OAuth %s response: %w", op, err)
	}
	if result.Error != "" {
		// GitHub returns 200 OK with a JSON `error` field for normal OAuth
		// failure modes (bad_verification_code, bad_refresh_token, ...).
		if op == "refresh" && result.Error == "bad_refresh_token" {
			return TokenResponse{}, fmt.Errorf("GitHub OAuth refresh error: %s", result.Error)
		}
		return TokenResponse{}, fmt.Errorf("GitHub OAuth %s error: %s", op, result.Error)
	}
	if result.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("empty access_token from GitHub on %s", op)
	}
	return TokenResponse{
		AccessToken:           result.AccessToken,
		Scopes:                splitScopes(result.Scope),
		RefreshToken:          result.RefreshToken,
		AccessTokenExpiresIn:  time.Duration(result.ExpiresIn) * time.Second,
		RefreshTokenExpiresIn: time.Duration(result.RefreshTokenExpiresIn) * time.Second,
	}, nil
}

func (p *githubProvider) ValidateToken(ctx context.Context, token string) (Identity, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.cfg.UserAPI, nil)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("building GitHub user request: %w", err)}
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := p.client.Do(req)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("GitHub API unreachable: %w", err)}
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return Identity{}, fmt.Errorf("invalid token: GitHub returned %d", resp.StatusCode)
		case http.StatusForbidden, http.StatusTooManyRequests:
			return Identity{}, &UpstreamError{Err: fmt.Errorf("GitHub API returned %d", resp.StatusCode)}
		default:
			if resp.StatusCode >= 500 {
				return Identity{}, &UpstreamError{Err: fmt.Errorf("GitHub API returned %d", resp.StatusCode)}
			}
			return Identity{}, fmt.Errorf("invalid token: GitHub returned %d", resp.StatusCode)
		}
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return Identity{}, &UpstreamError{Err: fmt.Errorf("reading GitHub user response: %w", err)}
	}
	var user struct {
		Login string `json:"login"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &user); err != nil {
		return Identity{}, fmt.Errorf("decoding GitHub user response: %w", err)
	}
	if user.Login == "" {
		return Identity{}, fmt.Errorf("GitHub user response missing login")
	}

	return Identity{
		Provider:    "github",
		Subject:     user.Login,
		DisplayName: user.Name,
	}, nil
}

// splitScopes normalizes GitHub's comma-delimited scope string into a slice.
func splitScopes(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if s := strings.TrimSpace(p); s != "" {
			out = append(out, s)
		}
	}
	return out
}
