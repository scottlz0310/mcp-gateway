package proxy

import (
	"log/slog"
	"net/http"

	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// refreshingTransport is an http.RoundTripper that transparently handles
// upstream 401 responses by refreshing the upstream OAuth token and retrying
// the original request with the new token. This makes the refresh invisible
// to the HTTP client (Case A: transparent retry).
type refreshingTransport struct {
	base http.RoundTripper
	opts *UpstreamOAuthOptions
}

func (t *refreshingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusUnauthorized {
		return resp, err
	}

	subject := middleware.IdentityFromContext(req.Context())
	if subject == "" {
		slog.Warn("upstream OAuth 401 retry: no authenticated subject in context; skipping refresh",
			"route", t.opts.RouteName,
			"path", req.URL.Path,
		)
		return resp, nil
	}

	newRec, ok := t.opts.Refresher.RefreshAfter401(req.Context(), subject, t.opts.RouteName)
	if !ok {
		slog.Warn("upstream OAuth 401 retry: refresh failed; returning 401 to caller",
			"route", t.opts.RouteName,
			"path", req.URL.Path,
		)
		return resp, nil
	}

	// Close the original 401 body before retrying to avoid connection leaks.
	_ = resp.Body.Close()

	newReq := req.Clone(req.Context())
	newReq.Header.Set("Authorization", "Bearer "+newRec.AccessToken)
	slog.Info("upstream OAuth 401 retry: retrying request with refreshed token",
		"route", t.opts.RouteName,
		"path", req.URL.Path,
	)
	return t.base.RoundTrip(newReq)
}
