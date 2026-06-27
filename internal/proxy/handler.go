package proxy

import (
	"context"
	"crypto/sha256"
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
