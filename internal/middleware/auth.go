package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"log/slog"
)

type contextKey string

// ContextKeyIdentity carries the authenticated user identifier (provider's
// Identity.Subject) injected by Auth middleware. Renamed from the previous
// "github_login" — the value is now provider-agnostic.
const ContextKeyIdentity contextKey = "authenticated_user"
const ContextKeyToken contextKey = "auth_token"

// TokenValidator is implemented by auth.Handler.
type TokenValidator interface {
	ValidateToken(ctx context.Context, token string) (string, error)
}

type upstreamErrorer interface {
	IsUpstreamError() bool
}

// authOptions holds optional configuration for the Auth middleware.
type authOptions struct {
	baseURL string
}

// AuthOption configures the Auth middleware.
type AuthOption func(*authOptions)

// WithBaseURL sets the gateway base URL so that 401 responses include a
// resource_metadata parameter in the WWW-Authenticate header (RFC 9728)
// pointing to /.well-known/oauth-protected-resource. This enables MCP
// clients to discover the gateway OAuth flow for re-authentication instead
// of falling back to alternative auth methods (e.g. gh CLI).
func WithBaseURL(u string) AuthOption {
	return func(o *authOptions) { o.baseURL = strings.TrimRight(u, "/") }
}

// Auth returns a middleware that validates Bearer tokens via the configured
// OAuth provider.
func Auth(v TokenValidator, opts ...AuthOption) func(http.Handler) http.Handler {
	var options authOptions
	for _, opt := range opts {
		opt(&options)
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				writeUnauthorized(w, "missing_token",
					"No access token provided. Authenticate via the gateway OAuth flow.",
					options.baseURL)
				return
			}

			subject, err := v.ValidateToken(r.Context(), token)
			if err != nil {
				var ue upstreamErrorer
				if errors.As(err, &ue) {
					slog.Error("upstream error during auth", "err", err, "path", r.URL.Path)
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusServiceUnavailable)
					_ = json.NewEncoder(w).Encode(map[string]string{
						"error":             "upstream_error",
						"error_description": "The upstream MCP server is temporarily unavailable. Please try again later.",
					})
					return
				}
				slog.Warn("auth failed", "err", err, "path", r.URL.Path)
				writeUnauthorized(w, "invalid_token",
					"Access token expired or invalid. Re-authenticate via the gateway OAuth flow.",
					options.baseURL)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyIdentity, subject)
			ctx = context.WithValue(ctx, ContextKeyToken, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// writeUnauthorized writes an RFC 6750 §3.1 compliant 401 Unauthorized response.
// For token validation failures (invalid_token), the WWW-Authenticate header
// includes error and error_description attributes.
// When baseURL is non-empty, resource_metadata (RFC 9728) is added to guide
// MCP clients to the gateway's OAuth re-authentication flow.
func writeUnauthorized(w http.ResponseWriter, errCode, errDesc, baseURL string) {
	parts := []string{`Bearer realm="mcp-gateway"`}
	if errCode != "missing_token" {
		// Per RFC 6750 §3.1, error attributes only apply to token validation failures,
		// not to requests that simply lack authentication.
		parts = append(parts, fmt.Sprintf(`error=%q, error_description=%q`, errCode, errDesc))
	}
	if baseURL != "" {
		parts = append(parts, fmt.Sprintf(`resource_metadata=%q`, baseURL+"/.well-known/oauth-protected-resource"))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errCode,
		"error_description": errDesc,
	})
}

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	fields := strings.Fields(h)
	if len(fields) == 2 && strings.EqualFold(fields[0], "bearer") {
		return fields[1]
	}
	return ""
}

// IdentityFromContext retrieves the authenticated user identifier injected by
// Auth middleware.
func IdentityFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyIdentity).(string)
	return v
}

// TokenFromContext retrieves the bearer token injected by Auth middleware.
func TokenFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ContextKeyToken).(string)
	return v
}
