package proxy

import (
	"crypto/sha256"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// TokenInvalidator is implemented by auth.Handler.
type TokenInvalidator interface {
	InvalidateCachedToken(token string)
}

// NewHandler returns an HTTP handler that reverse-proxies authenticated
// requests to the upstream MCP server. It performs header sanitization,
// injects the verified user identifier as X-Authenticated-User (and the
// legacy X-GitHub-Login during the migration window), and invalidates the
// token cache when the upstream returns HTTP 401.
func NewHandler(upstream *url.URL, inv TokenInvalidator) http.Handler {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(upstream)

			pr.Out.Header.Del("X-Forwarded-For")
			pr.Out.Header.Del("X-Real-Ip")
			pr.Out.Header.Del("X-Authenticated-User")
			pr.Out.Header.Del("X-GitHub-Login")
			pr.Out.Header.Del("X-Forwarded-Host")
			pr.Out.Header.Del("X-Forwarded-Proto")

			// Normalize Authorization from context to prevent client spoofing.
			pr.Out.Header.Del("Authorization")
			if token := middleware.TokenFromContext(pr.In.Context()); token != "" {
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
			)
		},

		ModifyResponse: func(resp *http.Response) error {
			if resp.StatusCode == http.StatusUnauthorized && inv != nil {
				if token := extractBearer(resp.Request); token != "" {
					inv.InvalidateCachedToken(token)
					slog.Warn("upstream rejected token; cache invalidated",
						"path", resp.Request.URL.Path,
						"token_hash", tokenHash(token),
					)
				}
			}
			slog.Info("proxy response",
				"upstream_status", resp.StatusCode,
				"path", resp.Request.URL.Path,
			)
			return nil
		},
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
