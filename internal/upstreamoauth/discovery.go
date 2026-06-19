package upstreamoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthServerMetadata は RFC 8414 §3.2 Authorization Server Metadata。
// 必須フィールド + DCR に必要なフィールドのみ定義する。
type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	ScopesSupported               []string `json:"scopes_supported,omitempty"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported,omitempty"`
}

// ProtectedResourceMetadata は RFC 9728 §3 Protected Resource Metadata。
type ProtectedResourceMetadata struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

// DefaultHTTPTimeout is the timeout applied to each discovery HTTP request.
const DefaultHTTPTimeout = 10 * time.Second

// DiscoverFromIssuer retrieves RFC 8414 Authorization Server Metadata for
// the given issuer URL. issuerURL must be a normalized absolute URL without
// a trailing slash.
func DiscoverFromIssuer(ctx context.Context, client *http.Client, issuerURL string) (*AuthServerMetadata, error) {
	wellKnownURL, err := buildASMetaURL(issuerURL)
	if err != nil {
		return nil, fmt.Errorf("building AS metadata URL for %q: %w", issuerURL, err)
	}
	meta, err := fetchJSON[AuthServerMetadata](ctx, client, wellKnownURL)
	if err != nil {
		return nil, fmt.Errorf("AS metadata discovery for %q: %w", issuerURL, err)
	}
	if meta.Issuer == "" || meta.AuthorizationEndpoint == "" || meta.TokenEndpoint == "" {
		return nil, fmt.Errorf("AS metadata from %q is missing required fields (issuer/authorization_endpoint/token_endpoint)", wellKnownURL)
	}
	return meta, nil
}

// DiscoverFromResource performs RFC 9728 → RFC 8414 two-step discovery using
// the upstream resource URL. resourceURL is the upstream host+path the gateway
// routes to (e.g. "https://mcp.example.com/sse").
func DiscoverFromResource(ctx context.Context, client *http.Client, resourceURL string) (*AuthServerMetadata, error) {
	prmURL, err := buildPRMURL(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("building PRM URL for %q: %w", resourceURL, err)
	}
	prm, err := fetchJSON[ProtectedResourceMetadata](ctx, client, prmURL)
	if err != nil {
		return nil, fmt.Errorf("PRM discovery at %q: %w", prmURL, err)
	}
	if len(prm.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("PRM at %q contains no authorization_servers", prmURL)
	}
	issuerURL := strings.TrimRight(prm.AuthorizationServers[0], "/")
	meta, err := DiscoverFromIssuer(ctx, client, issuerURL)
	if err != nil {
		return nil, fmt.Errorf("AS metadata discovery (via PRM %q): %w", prmURL, err)
	}
	return meta, nil
}

// buildPRMURL constructs the RFC 9728 §3 well-known PRM URL:
//
//	{scheme}://{host}/.well-known/oauth-protected-resource{path}
func buildPRMURL(resourceURL string) (string, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return "", fmt.Errorf("parsing resource URL: %w", err)
	}
	path := strings.TrimRight(u.Path, "/")
	out := *u
	out.Path = "/.well-known/oauth-protected-resource" + path
	out.RawQuery = ""
	out.Fragment = ""
	return out.String(), nil
}

// buildASMetaURL constructs the RFC 8414 §3.1 well-known URL by inserting
// "/.well-known/" between the host component and the path component of the
// issuer identifier.
//
//	issuer = "https://example.com"           → "https://example.com/.well-known/oauth-authorization-server"
//	issuer = "https://example.com/tenant1"   → "https://example.com/.well-known/oauth-authorization-server/tenant1"
func buildASMetaURL(issuerURL string) (string, error) {
	u, err := url.Parse(issuerURL)
	if err != nil {
		return "", fmt.Errorf("parsing issuer URL: %w", err)
	}
	issuerPath := strings.TrimRight(u.Path, "/")
	out := *u
	out.Path = "/.well-known/oauth-authorization-server" + issuerPath
	out.RawQuery = ""
	out.Fragment = ""
	return out.String(), nil
}

// fetchJSON performs an HTTP GET to rawURL and JSON-decodes the response body
// into a value of type T. Non-200 responses are returned as errors.
func fetchJSON[T any](ctx context.Context, client *http.Client, rawURL string) (*T, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request for %s: %w", rawURL, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("GET %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: unexpected status %d", rawURL, resp.StatusCode)
	}
	var result T
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response from %s: %w", rawURL, err)
	}
	return &result, nil
}
