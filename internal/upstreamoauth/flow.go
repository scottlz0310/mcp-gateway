package upstreamoauth

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

const stateTTL = 10 * time.Minute

func generateStateKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewAuthorizeMiddleware returns middleware that acquires an upstream token for
// authenticated users that do not yet have one.
//
// When grant is "client_credentials", the token is fetched directly from the
// upstream token endpoint without user interaction. When grant is
// "authorization_code" (or empty, which defaults to "authorization_code"), the
// user is redirected to the upstream authorization endpoint via PKCE.
//
// The middleware must sit between the gateway Auth middleware (which sets the
// identity in context) and the proxy handler.
func NewAuthorizeMiddleware(
	routeName string,
	upstreamOAuth string,
	upstreamOAuthScope string,
	grant string,
	resourceURL string,
	manager *Manager,
	stateStore StateStore,
	tokenStore auth.UpstreamTokenStore,
	publicURL string,
) func(http.Handler) http.Handler {
	trimmedPublicURL := strings.TrimRight(publicURL, "/")
	if grant == "" {
		grant = "authorization_code"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := middleware.IdentityFromContext(r.Context())
			if subject == "" {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}

			if rec, ok := tokenStore.Lookup(subject, routeName); ok {
				if grantMatches(rec.Grant, grant) {
					next.ServeHTTP(w, r)
					return
				}
				// grant mismatch: delete stale token and fall through to re-acquisition
				_ = tokenStore.Delete(subject, routeName)
			}

			rec, err := manager.EnsureClient(r.Context(), routeName, upstreamOAuth, resourceURL, grant)
			if err != nil {
				slog.Error("upstream OAuth: EnsureClient failed", "route", routeName, "err", err)
				http.Error(w, "upstream OAuth configuration error", http.StatusBadGateway)
				return
			}

			if grant == "client_credentials" {
				tokenResp, err := fetchClientCredentialsToken(r.Context(), manager.httpClient, rec, upstreamOAuthScope)
				if err != nil {
					slog.Error("upstream OAuth: client_credentials token fetch failed", "route", routeName, "err", err)
					http.Error(w, "upstream OAuth error", http.StatusBadGateway)
					return
				}
				if tokenResp.ExpiresIn <= 0 {
					slog.Error("upstream OAuth: client_credentials token missing required expires_in",
						"route", routeName, "token_endpoint", rec.TokenEndpoint)
					http.Error(w, "upstream token missing required expiry", http.StatusBadGateway)
					return
				}
				expiresAt := time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
				if err := tokenStore.Save(subject, routeName, auth.UpstreamTokenRecord{
					Grant:       "client_credentials",
					Issuer:      rec.Issuer,
					AccessToken: tokenResp.AccessToken,
					ExpiresAt:   expiresAt,
					Scope:       tokenResp.Scope,
				}); err != nil {
					slog.Error("upstream OAuth: failed to save client_credentials token", "route", routeName, "err", err)
					http.Error(w, "failed to save token", http.StatusInternalServerError)
					return
				}
				slog.Info("upstream OAuth: client_credentials token acquired", "route", routeName)
				next.ServeHTTP(w, r)
				return
			}

			// authorization_code flow: redirect user to upstream authorization endpoint.
			codeVerifier, err := GenerateCodeVerifier()
			if err != nil {
				slog.Error("upstream OAuth: code_verifier generation failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}
			stateKey, err := generateStateKey()
			if err != nil {
				slog.Error("upstream OAuth: state generation failed", "err", err)
				http.Error(w, "internal error", http.StatusInternalServerError)
				return
			}

			stateStore.Save(stateKey, OAuthState{
				Subject:      subject,
				RouteName:    routeName,
				OriginalPath: r.URL.RequestURI(),
				CodeVerifier: codeVerifier,
				ExpiresAt:    time.Now().Add(stateTTL),
			})

			redirectURI := fmt.Sprintf("%s/upstream/callback/%s",
				trimmedPublicURL,
				url.PathEscape(routeName),
			)
			authURL, err := url.Parse(rec.AuthorizationEndpoint)
			if err != nil {
				slog.Error("upstream OAuth: invalid authorization_endpoint", "url", rec.AuthorizationEndpoint, "err", err)
				http.Error(w, "upstream OAuth configuration error", http.StatusBadGateway)
				return
			}
			q := authURL.Query()
			q.Set("client_id", rec.ClientID)
			q.Set("redirect_uri", redirectURI)
			if upstreamOAuthScope != "" {
				q.Set("scope", upstreamOAuthScope)
			}
			q.Set("response_type", "code")
			q.Set("code_challenge", S256Challenge(codeVerifier))
			q.Set("code_challenge_method", "S256")
			q.Set("state", stateKey)
			authURL.RawQuery = q.Encode()

			// Return 200 + JSON-RPC error instead of 302 so MCP clients don't
			// treat the response as a connection failure and restart the auth flow,
			// which would overwrite the pending state and cause an infinite loop.
			writeUpstreamAuthRequired(w, routeName, authURL.String())
		})
	}
}

func writeUpstreamAuthRequired(w http.ResponseWriter, routeName, authorizationURL string) {
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      nil,
		"error": map[string]any{
			"code":    -32001,
			"message": fmt.Sprintf("%s authorization required. Open the URL in 'data.authorization_url' in your browser, then retry.", routeName),
			"data": map[string]any{
				"type":              "upstream_authorization_required",
				"authorization_url": authorizationURL,
			},
		},
	})
	if err != nil {
		slog.Error("upstream OAuth: failed to marshal upstream_auth_required response", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// fetchClientCredentialsToken obtains an access token from rec.TokenEndpoint
// using the client_credentials grant type. The returned response is never nil
// when err is nil, and AccessToken is guaranteed to be non-empty.
func fetchClientCredentialsToken(ctx context.Context, httpClient *http.Client, rec ClientRecord, scope string) (*tokenExchangeResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	if scope != "" {
		form.Set("scope", scope)
	}
	form.Set("client_id", rec.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rec.TokenEndpoint,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("creating client_credentials request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if rec.ClientSecret != "" {
		req.SetBasicAuth(rec.ClientID, rec.ClientSecret)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", rec.TokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, tokenEndpointError(rec.TokenEndpoint, resp.StatusCode, resp.Body)
	}

	var tr tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, fmt.Errorf("decoding token response from %s: %w", rec.TokenEndpoint, err)
	}
	if tr.AccessToken == "" {
		return nil, fmt.Errorf("token response from %s missing access_token", rec.TokenEndpoint)
	}
	return &tr, nil
}
