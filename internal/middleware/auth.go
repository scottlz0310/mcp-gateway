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
	baseURL             string
	resourceMetadataURL string
}

// AuthOption configures the Auth middleware.
type AuthOption func(*authOptions)

// WithBaseURL sets the gateway base URL so that 401 responses include a
// resource_metadata parameter in the WWW-Authenticate header (RFC 9728)
// pointing to /.well-known/oauth-protected-resource. This enables MCP
// clients to discover the gateway OAuth flow for re-authentication instead
// of falling back to alternative auth methods (e.g. gh CLI).
//
// When WithResourceMetadataURL is also supplied, it takes precedence and the
// gateway-wide PRM URL derived from baseURL is ignored.
func WithBaseURL(u string) AuthOption {
	return func(o *authOptions) { o.baseURL = strings.TrimRight(u, "/") }
}

// WithResourceMetadataURL sets the absolute URL advertised in the
// resource_metadata parameter of the 401 WWW-Authenticate header. Use this
// per route to point clients at a route-scoped Protected Resource Metadata
// document (MCP Authorization Spec 2025-06-18) instead of the gateway-wide
// one. The URL is emitted verbatim, so callers should pass the full
// well-known URL (e.g. "https://gw/.well-known/oauth-protected-resource/mcp/foo").
func WithResourceMetadataURL(u string) AuthOption {
	return func(o *authOptions) { o.resourceMetadataURL = strings.TrimSpace(u) }
}

// Auth returns a middleware that validates Bearer tokens via the configured
// OAuth provider.
func Auth(v TokenValidator, opts ...AuthOption) func(http.Handler) http.Handler {
	var options authOptions
	for _, opt := range opts {
		opt(&options)
	}
	resourceMetadataURL := resolveResourceMetadataURL(options)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				writeUnauthorized(w, "invalid_request",
					"No access token provided. Authenticate via the gateway OAuth flow.",
					resourceMetadataURL)
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
					resourceMetadataURL)
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyIdentity, subject)
			ctx = context.WithValue(ctx, ContextKeyToken, token)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// resolveResourceMetadataURL chooses the resource_metadata URL for the
// WWW-Authenticate header. An explicitly configured WithResourceMetadataURL
// wins; otherwise the gateway-wide /.well-known/oauth-protected-resource is
// derived from baseURL. Returns an empty string when neither is set, in which
// case the parameter is omitted entirely.
func resolveResourceMetadataURL(o authOptions) string {
	if o.resourceMetadataURL != "" {
		return o.resourceMetadataURL
	}
	if o.baseURL != "" {
		return o.baseURL + "/.well-known/oauth-protected-resource"
	}
	return ""
}

// writeUnauthorized writes an RFC 6750 §3.1 compliant 401 Unauthorized response.
// For token validation failures (invalid_token), the WWW-Authenticate header
// includes error and error_description attributes.
// When resourceMetadataURL is non-empty, resource_metadata (RFC 9728) is added
// to guide MCP clients to the appropriate Protected Resource Metadata document.
func writeUnauthorized(w http.ResponseWriter, errCode, errDesc, resourceMetadataURL string) {
	parts := []string{`Bearer realm="mcp-gateway"`}
	if errCode == "invalid_token" {
		// By design, error= is only included for token validation failures (invalid_token).
		// For missing-token requests (invalid_request), we intentionally omit error= to avoid
		// leaking that a credential is required on unauthenticated probes.
		parts = append(parts, fmt.Sprintf(`error=%q, error_description=%q`, errCode, errDesc))
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
