package upstreamoauth

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
)

// tokenEndpointError builds a loggable error for a non-2xx token endpoint
// response. The response body must never be embedded: the gateway submits
// secrets (authorization code, refresh token, client secret) to the token
// endpoint, and an AS reflecting them into an error body would leak them
// into logs. Only the HTTP status and the RFC 6749 §5.2 "error" code —
// classified against the known-code allowlist, with unknown values collapsed
// to "unknown_error" — are kept. See docs/token-log-audit.md.
func tokenEndpointError(endpoint string, statusCode int, body io.Reader) error {
	var payload struct {
		Error string `json:"error"`
	}
	code := ""
	if err := json.NewDecoder(io.LimitReader(body, 4<<10)).Decode(&payload); err == nil {
		code = provider.NormalizeOAuthErrorCode(payload.Error)
	}
	if code == "" {
		return fmt.Errorf("token endpoint %s: status %d", endpoint, statusCode)
	}
	return fmt.Errorf("token endpoint %s: status %d (oauth_error=%s)", endpoint, statusCode, code)
}
