package upstreamoauth

import (
	"crypto/rand"
	"encoding/base64"
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

// NewAuthorizeMiddleware returns middleware that redirects authenticated users
// to the upstream authorization endpoint when they have no valid upstream token.
//
// The middleware must sit between the gateway Auth middleware (which sets the
// identity in context) and the proxy handler.
func NewAuthorizeMiddleware(
	routeName string,
	upstreamOAuth string,
	upstreamOAuthScope string,
	resourceURL string,
	manager *Manager,
	stateStore StateStore,
	tokenStore auth.UpstreamTokenStore,
	publicURL string,
) func(http.Handler) http.Handler {
	trimmedPublicURL := strings.TrimRight(publicURL, "/")
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := middleware.IdentityFromContext(r.Context())
			if subject == "" {
				http.Error(w, "unauthenticated", http.StatusUnauthorized)
				return
			}

			if _, ok := tokenStore.Lookup(subject, routeName); ok {
				next.ServeHTTP(w, r)
				return
			}

			rec, err := manager.EnsureClient(r.Context(), routeName, upstreamOAuth, resourceURL)
			if err != nil {
				slog.Error("upstream OAuth: EnsureClient failed", "route", routeName, "err", err)
				http.Error(w, "upstream OAuth configuration error", http.StatusBadGateway)
				return
			}

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

			http.Redirect(w, r, authURL.String(), http.StatusFound)
		})
	}
}
