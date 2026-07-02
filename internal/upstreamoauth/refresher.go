package upstreamoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
)

const defaultProactiveWindow = 5 * time.Minute

// Refresher handles proactive and 401-triggered upstream OAuth token refresh.
// Concurrent refresh calls for the same (subject, routeName) pair are coalesced
// via singleflight so that only one HTTP round-trip to the token endpoint occurs.
type Refresher struct {
	tokenStore      auth.UpstreamTokenStore
	manager         *Manager
	httpClient      *http.Client
	sfGroup         singleflight.Group
	proactiveWindow time.Duration
}

// NewRefresher creates a Refresher. If httpClient is nil, a client with
// DefaultHTTPTimeout is used.
func NewRefresher(tokenStore auth.UpstreamTokenStore, manager *Manager, httpClient *http.Client) *Refresher {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: DefaultHTTPTimeout}
	}
	return &Refresher{
		tokenStore:      tokenStore,
		manager:         manager,
		httpClient:      httpClient,
		proactiveWindow: defaultProactiveWindow,
	}
}

// EnsureFreshToken returns a valid token, refreshing proactively when ExpiresAt
// is within the proactive window and a refresh_token is available.
//
// Returns (rec, true) when a valid token is available (unchanged or refreshed).
// Returns (zero, false) when a permanent refresh failure required deleting the token.
// Returns (rec, true) when refresh is skipped (no expiry info, no refresh_token, or
// transient failure); the caller uses the existing token as-is.
func (r *Refresher) EnsureFreshToken(ctx context.Context, subject, routeName string, rec auth.UpstreamTokenRecord) (auth.UpstreamTokenRecord, bool) {
	if rec.ExpiresAt.IsZero() {
		return rec, true
	}
	if time.Until(rec.ExpiresAt) > r.proactiveWindow {
		return rec, true
	}
	if rec.RefreshToken == "" {
		return rec, true
	}
	return r.doRefresh(ctx, subject, routeName, rec.RefreshToken, false)
}

// RefreshAfter401 attempts to refresh the token using the stored refresh_token
// after an upstream 401. On permanent failure, the token entry is deleted and
// (zero, false) is returned. On transient failure, returns the existing record
// and true so the caller can return the 401 to the client rather than deleting
// a token that might recover later.
func (r *Refresher) RefreshAfter401(ctx context.Context, subject, routeName string) (auth.UpstreamTokenRecord, bool) {
	// Use LookupForRefresh so that an expired access token does not prevent
	// retrieval of a still-valid refresh_token.
	existing, ok := r.tokenStore.LookupForRefresh(subject, routeName)
	if !ok || existing.RefreshToken == "" {
		_ = r.tokenStore.Delete(subject, routeName)
		return auth.UpstreamTokenRecord{}, false
	}
	return r.doRefresh(ctx, subject, routeName, existing.RefreshToken, true)
}

// doRefresh executes the refresh grant, coalescing concurrent calls via singleflight.
// force=true skips the proactive-window re-check so that 401-triggered calls always
// attempt a network round-trip even when the stored token appears unexpired.
func (r *Refresher) doRefresh(ctx context.Context, subject, routeName, refreshToken string, force bool) (auth.UpstreamTokenRecord, bool) {
	sfKey := subject + "\x00" + routeName

	type sfResult struct {
		rec auth.UpstreamTokenRecord
		ok  bool
	}

	v, _, _ := r.sfGroup.Do(sfKey, func() (any, error) {
		// Re-check: a concurrent goroutine coalesced into this singleflight may
		// have already refreshed. Skip if the refresh_token rotated (another
		// goroutine already succeeded) or, for proactive calls only, the token
		// is now valid with sufficient runway.
		if latest, ok := r.tokenStore.Lookup(subject, routeName); ok {
			alreadyRotated := latest.RefreshToken != refreshToken
			hasRunway := !latest.ExpiresAt.IsZero() && time.Until(latest.ExpiresAt) > r.proactiveWindow
			if alreadyRotated || (!force && hasRunway) {
				return sfResult{rec: latest, ok: true}, nil
			}
		}

		clientRec, hasClient := r.manager.LoadClient(routeName)
		if !hasClient || clientRec.TokenEndpoint == "" {
			slog.Warn("upstream OAuth refresh: no client registration for route", "route", routeName)
			if existing, ok := r.tokenStore.Lookup(subject, routeName); ok {
				return sfResult{rec: existing, ok: true}, nil
			}
			return sfResult{}, nil
		}

		newToken, permanent, err := r.callRefreshEndpoint(ctx, clientRec, refreshToken)
		if err != nil {
			if permanent {
				slog.Warn("upstream OAuth refresh: permanent failure, deleting token",
					"route", routeName, "err", err)
				_ = r.tokenStore.Delete(subject, routeName)
				return sfResult{}, nil
			}
			slog.Warn("upstream OAuth refresh: transient failure, keeping existing token",
				"route", routeName, "err", err)
			if existing, ok := r.tokenStore.Lookup(subject, routeName); ok {
				return sfResult{rec: existing, ok: true}, nil
			}
			return sfResult{}, nil
		}

		// Reject refresh responses without expires_in: saving a zero ExpiresAt would
		// make UpstreamTokenStore.Lookup treat the refreshed token as permanently valid,
		// which is inconsistent with callback.go's policy. Keep the existing token instead.
		if newToken.ExpiresIn <= 0 {
			slog.Warn("upstream OAuth refresh: response missing expires_in, keeping existing token",
				"route", routeName)
			if existing, ok := r.tokenStore.Lookup(subject, routeName); ok {
				return sfResult{rec: existing, ok: true}, nil
			}
			return sfResult{}, nil
		}

		// Preserve old refresh_token when AS does not rotate it.
		keepRefreshToken := newToken.RefreshToken
		if keepRefreshToken == "" {
			keepRefreshToken = refreshToken
		}

		updated := auth.UpstreamTokenRecord{
			Issuer:       clientRec.Issuer,
			AccessToken:  newToken.AccessToken,
			RefreshToken: keepRefreshToken,
			ExpiresAt:    time.Now().Add(time.Duration(newToken.ExpiresIn) * time.Second),
			Scope:        newToken.Scope,
		}
		if err := r.tokenStore.Save(subject, routeName, updated); err != nil {
			slog.Warn("upstream OAuth refresh: failed to save refreshed token",
				"route", routeName, "err", err)
		}
		slog.Info("upstream OAuth: token refreshed", "route", routeName)
		return sfResult{rec: updated, ok: true}, nil
	})

	if v == nil {
		return auth.UpstreamTokenRecord{}, false
	}
	result := v.(sfResult)
	return result.rec, result.ok
}

// callRefreshEndpoint sends grant_type=refresh_token to the token endpoint.
// Returns (response, permanent, error).
// permanent=true indicates the refresh_token is invalid/revoked (4xx except 429),
// meaning the caller should delete the token entry and require re-authorization.
func (r *Refresher) callRefreshEndpoint(ctx context.Context, rec ClientRecord, refreshToken string) (*tokenExchangeResponse, bool, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", rec.ClientID)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rec.TokenEndpoint,
		bytes.NewBufferString(form.Encode()))
	if err != nil {
		return nil, false, fmt.Errorf("creating refresh request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if rec.ClientSecret != "" {
		req.SetBasicAuth(rec.ClientID, rec.ClientSecret)
	}

	resp, err := r.httpClient.Do(req)
	if err != nil {
		return nil, false, fmt.Errorf("POST %s: %w", rec.TokenEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 4xx (except 429 Too Many Requests) = permanent failure:
	// the refresh_token is invalid or revoked by the AS.
	permanent := resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests
	if resp.StatusCode != http.StatusOK {
		return nil, permanent, tokenEndpointError(rec.TokenEndpoint, resp.StatusCode, resp.Body)
	}

	var tr tokenExchangeResponse
	if err := json.NewDecoder(resp.Body).Decode(&tr); err != nil {
		return nil, false, fmt.Errorf("decoding refresh response: %w", err)
	}
	if tr.AccessToken == "" {
		return nil, true, fmt.Errorf("refresh response missing access_token")
	}
	return &tr, false, nil
}
