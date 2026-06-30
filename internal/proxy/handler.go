package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// TokenInvalidator is implemented by auth.Handler.
type TokenInvalidator interface {
	InvalidateCachedToken(token string)
}

// ProviderTokenSource resolves the current provider access token for an authenticated subject.
// Implemented by auth.Handler via EnsureFreshAccessTokenForSubject.
type ProviderTokenSource interface {
	EnsureFreshAccessTokenForSubject(ctx context.Context, subject string) (auth.DelegatedAccessResult, error)
}

// providerTokenContextKey is the context key used to pass a resolved provider access token
// from NewProviderTokenMiddleware into the proxy Rewrite function and ModifyResponse handler.
type providerTokenContextKey struct{}

// UpstreamTokenRefresher handles proactive and 401-triggered upstream OAuth
// token refresh. Implemented by upstreamoauth.Refresher.
type UpstreamTokenRefresher interface {
	EnsureFreshToken(ctx context.Context, subject, routeName string, rec auth.UpstreamTokenRecord) (auth.UpstreamTokenRecord, bool)
	RefreshAfter401(ctx context.Context, subject, routeName string) (auth.UpstreamTokenRecord, bool)
}

// UpstreamOAuthOptions configures per-user upstream OAuth token injection.
// When non-nil, the proxy reads the upstream access token from TokenStore
// instead of forwarding the gateway client token.
// Refresher is optional: when set, proactive refresh is attempted before
// injection and 401 responses trigger transparent token refresh + retry.
type UpstreamOAuthOptions struct {
	TokenStore auth.UpstreamTokenStore
	RouteName  string
	Refresher  UpstreamTokenRefresher // nil = no proactive/auto refresh
}

// NewProviderTokenMiddleware returns a handler that resolves the authenticated subject's
// provider access token (e.g. the GitHub user token in builtin mode) via src, stores it in
// the request context, and delegates to next. If resolution fails for any reason the request
// is rejected with a 401 that includes a WWW-Authenticate header pointing to resourceMetadataURL
// (when non-empty) so that MCP clients can re-authenticate. next is never called on failure.
//
// This middleware must be placed after the gateway Auth middleware (which sets the identity in
// context) and before the proxy handler (which reads the token from context).
func NewProviderTokenMiddleware(src ProviderTokenSource, resourceMetadataURL string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject := middleware.IdentityFromContext(r.Context())
		if subject == "" {
			// This should not happen when the middleware chain is correctly ordered.
			// An empty subject indicates a misconfigured handler chain (e.g. provider
			// token middleware placed before gateway Auth middleware).
			slog.Error("provider token: authenticated subject missing from context; check middleware ordering",
				"path", r.URL.Path,
			)
			writeProviderTokenUnauthorized(w, "authenticated subject not found in request context", resourceMetadataURL)
			return
		}
		result, err := src.EnsureFreshAccessTokenForSubject(r.Context(), subject)
		if err != nil {
			var logMsg string
			switch {
			case errors.Is(err, auth.ErrSubjectNotFound):
				logMsg = "provider token: subject not found; re-authentication required"
			case errors.Is(err, auth.ErrRotationFailed):
				logMsg = "provider token: token rotation failed; re-authentication required"
			default:
				logMsg = "provider token: resolution failed; re-authentication required"
			}
			slog.Warn(logMsg, "path", r.URL.Path)
			writeProviderTokenUnauthorized(w, "provider access token unavailable; re-authenticate via the gateway OAuth flow", resourceMetadataURL)
			return
		}
		ctx := context.WithValue(r.Context(), providerTokenContextKey{}, result.AccessToken)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeProviderTokenUnauthorized writes a 401 response with WWW-Authenticate (RFC 6750 §3.1).
func writeProviderTokenUnauthorized(w http.ResponseWriter, errDesc, resourceMetadataURL string) {
	parts := []string{
		`Bearer realm="mcp-gateway"`,
		fmt.Sprintf(`error=%q, error_description=%q`, "invalid_token", errDesc),
	}
	if resourceMetadataURL != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata=%q`, resourceMetadataURL))
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_token",
		"error_description": errDesc,
	})
}

// NewHandler returns an HTTP handler that reverse-proxies authenticated
// requests to the upstream MCP server. It performs header sanitization,
// injects the verified user identifier as X-Authenticated-User (and the
// legacy X-GitHub-Login during the migration window), and handles upstream
// HTTP 401 responses according to the configured token source.
//
// Token injection priority:
//  1. upstreamOAuth non-nil → per-user token from UpstreamTokenStore,
//     with optional proactive refresh via UpstreamOAuthOptions.Refresher.
//  2. upstreamBearerTokenEnv non-empty → token from named env var.
//  3. otherwise → gateway client OAuth token from context.
//
// Upstream 401 handling:
//   - upstreamOAuth with Refresher: refreshingTransport intercepts the 401,
//     calls RefreshAfter401, and retries with the new token transparently.
//     If refresh fails, the 401 propagates and ModifyResponse logs it.
//   - upstreamOAuth without Refresher: the stale token is deleted from
//     TokenStore so the next request triggers re-authorization.
//   - upstreamBearerTokenEnv: logs a warning; env var token must be rotated.
//   - otherwise: invalidates the gateway client token cache.
func NewHandler(upstream *url.URL, inv TokenInvalidator, upstreamBearerTokenEnv string, prefix string, upstreamOAuth *UpstreamOAuthOptions) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			// Strip prefix before SetURL so that SetURL correctly joins
			// upstream.Path + stripped_path (SetURL appends pr.Out.URL.Path).
			exactPrefix := false
			if prefix != "" && prefix != "/" {
				stripped := strings.TrimPrefix(pr.Out.URL.Path, prefix)
				if stripped == "" {
					exactPrefix = true
					stripped = "/"
				}
				pr.Out.URL.Path = stripped
				if pr.Out.URL.RawPath != "" {
					rawStripped := strings.TrimPrefix(pr.Out.URL.RawPath, prefix)
					if rawStripped == "" {
						rawStripped = "/"
					}
					pr.Out.URL.RawPath = rawStripped
				}
			}

			pr.SetURL(upstream)
			if exactPrefix && upstream.Path != "" {
				// SetURL appends "/" when joining a non-empty base path with
				// the exact route prefix. Preserve the configured base path.
				pr.Out.URL.Path = upstream.Path
				pr.Out.URL.RawPath = upstream.RawPath
			}

			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Real-Ip")
			pr.Out.Header.Del("Forwarded")
			pr.Out.Header.Del("X-Authenticated-User")
			pr.Out.Header.Del("X-GitHub-Login")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")

			// Always strip client-supplied Authorization first to prevent spoofing,
			// then inject the appropriate upstream credential.
			pr.Out.Header.Del("Authorization")
			if upstreamOAuth != nil {
				// Per-user upstream OAuth token: inject the user's upstream access token.
				// NewAuthorizeMiddleware guarantees a token exists before reaching here;
				// the Lookup is defensive against misconfigured middleware chains.
				subject := middleware.IdentityFromContext(pr.In.Context())
				if rec, ok := upstreamOAuth.TokenStore.Lookup(subject, upstreamOAuth.RouteName); ok {
					if upstreamOAuth.Refresher != nil {
						rec, ok = upstreamOAuth.Refresher.EnsureFreshToken(pr.In.Context(), subject, upstreamOAuth.RouteName, rec)
					}
					if ok {
						pr.Out.Header.Set("Authorization", "Bearer "+rec.AccessToken)
					} else {
						slog.Warn("upstream OAuth: proactive refresh failed; forwarding without Authorization",
							"route", upstreamOAuth.RouteName,
							"path", pr.Out.URL.Path,
						)
					}
				} else {
					slog.Warn("upstream OAuth: token not found at proxy injection; request forwarded without Authorization",
						"route", upstreamOAuth.RouteName,
						"path", pr.Out.URL.Path,
					)
				}
			} else if upstreamBearerTokenEnv != "" {
				// Upstream credential injection: read the named env var at request time.
				// A warning is emitted when the env var is unset or empty so that
				// rotated or missing credentials are visible in logs.
				if token := strings.TrimSpace(os.Getenv(upstreamBearerTokenEnv)); token != "" {
					pr.Out.Header.Set("Authorization", "Bearer "+token)
				} else {
					slog.Warn("upstream credential env var is unset or empty; request forwarded without Authorization",
						"env_var", upstreamBearerTokenEnv,
						"path", pr.Out.URL.Path,
					)
				}
			} else if pt, ok := pr.In.Context().Value(providerTokenContextKey{}).(string); ok && pt != "" {
				// Provider token delegation: NewProviderTokenMiddleware resolved the subject's
				// provider access token and stored it in context. Inject it as the upstream Bearer.
				// This path is only reached when upstream_provider_token=true on the route.
				pr.Out.Header.Set("Authorization", "Bearer "+pt)
			} else if token := middleware.TokenFromContext(pr.In.Context()); token != "" {
				pr.Out.Header.Set("Authorization", "Bearer "+token)
			}

			if subject := middleware.IdentityFromContext(pr.In.Context()); subject != "" {
				pr.Out.Header.Set("X-Authenticated-User", sanitizeHeaderValue(subject))
				// Legacy header retained during the migration window so that
				// upstream MCP services (github-mcp, copilot-review-mcp) keep
				// working until they migrate to X-Authenticated-User.
				pr.Out.Header.Set("X-GitHub-Login", sanitizeHeaderValue(subject))
			}

			slog.Info("proxy request",
				"user", middleware.IdentityFromContext(pr.In.Context()),
				"method", pr.Out.Method,
				"path", pr.Out.URL.Path,
				"token_hash", tokenHash(middleware.TokenFromContext(pr.In.Context())),
				"mcp_session_id_present", pr.Out.Header.Get("Mcp-Session-Id") != "",
			)
		},

		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusUnauthorized {
				if upstreamOAuth != nil {
					if upstreamOAuth.Refresher != nil {
						// refreshingTransport already attempted refresh+retry and deleted
						// the token on permanent failure. A 401 reaching ModifyResponse
						// means refresh failed; just log and let the 401 propagate.
						slog.Warn("upstream OAuth: upstream 401 after refresh attempt; re-authorization required",
							"route", upstreamOAuth.RouteName,
							"path", resp.Request.URL.Path,
						)
					} else {
						// No refresher: delete the stale token so the next request
						// triggers re-authorization via NewAuthorizeMiddleware.
						subject := middleware.IdentityFromContext(resp.Request.Context())
						if subject == "" {
							slog.Warn("upstream OAuth: upstream 401; no authenticated subject in context, stale token not deleted",
								"route", upstreamOAuth.RouteName,
								"path", resp.Request.URL.Path,
							)
						} else if err := upstreamOAuth.TokenStore.Delete(subject, upstreamOAuth.RouteName); err != nil {
							slog.Warn("upstream OAuth: upstream 401; failed to delete stale token, re-authorization may not trigger",
								"route", upstreamOAuth.RouteName,
								"path", resp.Request.URL.Path,
								"err", err,
							)
						} else {
							slog.Warn("upstream OAuth: upstream 401; token deleted, re-authorization required",
								"route", upstreamOAuth.RouteName,
								"path", resp.Request.URL.Path,
							)
						}
					}
				} else if upstreamBearerTokenEnv != "" {
					// The 401 came from an upstream-credential route.
					// This is a problem with the upstream API token, not the
					// client OAuth session — do NOT invalidate the client cache.
					slog.Warn("upstream rejected upstream credential; check env var token",
						"path", resp.Request.URL.Path,
						"env_var", upstreamBearerTokenEnv,
					)
				} else if _, usedProviderToken := resp.Request.Context().Value(providerTokenContextKey{}).(string); usedProviderToken {
					// The 401 came from a provider-token-delegated route.
					// The provider token may have expired between middleware resolution and
					// the upstream call. Do NOT invalidate the gateway JWT cache — it is
					// independent of the provider token lifecycle. The client can retry;
					// the middleware will attempt a fresh EnsureFreshAccessTokenForSubject.
					slog.Warn("upstream rejected provider token; provider access token may be stale",
						"path", resp.Request.URL.Path,
					)
				} else if inv != nil {
					if token := extractBearer(resp.Request); token != "" {
						inv.InvalidateCachedToken(token)
						slog.Warn("upstream rejected token; cache invalidated",
							"path", resp.Request.URL.Path,
							"token_hash", tokenHash(token),
						)
					}
				}
			}
			slog.Info("proxy response",
				"upstream_status", resp.StatusCode,
				"path", resp.Request.URL.Path,
				"mcp_session_id_present", resp.Header.Get("Mcp-Session-Id") != "",
			)
			return nil
		},
	}

	// When a Refresher is configured, wrap the default transport to intercept
	// upstream 401 responses and retry with a refreshed token transparently.
	if upstreamOAuth != nil && upstreamOAuth.Refresher != nil {
		rp.Transport = &refreshingTransport{
			base: http.DefaultTransport,
			opts: upstreamOAuth,
		}
	}

	return rp
}

func extractBearer(req *http.Request) string {
	auth := req.Header.Get("Authorization")
	const prefix = "Bearer "
	if len(auth) > len(prefix) && auth[:len(prefix)] == prefix {
		return auth[len(prefix):]
	}
	return ""
}

// headerSanitizer is a package-level replacer reused on every proxied request.
var headerSanitizer = strings.NewReplacer("\r", "", "\n", "")

// sanitizeHeaderValue strips CR and LF to prevent HTTP header injection.
func sanitizeHeaderValue(s string) string {
	return headerSanitizer.Replace(s)
}

// tokenHash returns the first 8 hex characters of SHA-256(token) for log correlation.
func tokenHash(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return fmt.Sprintf("%x", sum[:4])
}
