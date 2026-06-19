package upstreamoauth

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Manager orchestrates upstream OAuth metadata discovery and Dynamic Client
// Registration for gateway routes that have UpstreamOAuth configured.
//
// Discovery is performed lazily on the first EnsureClient call for each route;
// the result is cached in memory so subsequent calls skip the network round-trip.
// DCR is skipped when a ClientRecord with a non-empty ClientID already exists
// in the ClientStore (loaded from disk on startup).
type Manager struct {
	store      ClientStore
	httpClient *http.Client
	publicURL  string // gateway public base URL for redirect_uri construction

	mu    sync.RWMutex
	cache map[string]*AuthServerMetadata // keyed by route name
}

// NewManager creates a Manager backed by store. publicURL is the gateway's
// canonical base URL (e.g. "https://gateway.example.com"); it is used to
// construct the redirect_uri sent during DCR.
func NewManager(store ClientStore, publicURL string) *Manager {
	return &Manager{
		store:      store,
		httpClient: &http.Client{Timeout: DefaultHTTPTimeout},
		publicURL:  strings.TrimRight(publicURL, "/"),
		cache:      make(map[string]*AuthServerMetadata),
	}
}

// EnsureClient returns the ClientRecord for routeName, performing discovery
// and DCR if no valid registration exists yet.
//
//   - upstreamOAuth: "auto" (RFC 9728 + RFC 8414 two-step) or an absolute
//     issuer URL (RFC 8414 one-step).
//   - resourceURL: the upstream URL for "auto" discovery (e.g.
//     "https://mcp.example.com/sse"). Ignored when upstreamOAuth is an issuer URL.
func (m *Manager) EnsureClient(ctx context.Context, routeName, upstreamOAuth, resourceURL string) (ClientRecord, error) {
	if rec, ok := m.store.Load(routeName); ok && rec.ClientID != "" {
		return rec, nil
	}

	meta, err := m.discoverCached(ctx, routeName, upstreamOAuth, resourceURL)
	if err != nil {
		return ClientRecord{}, fmt.Errorf("upstream OAuth discovery for route %q: %w", routeName, err)
	}

	if meta.RegistrationEndpoint == "" {
		return ClientRecord{}, fmt.Errorf("upstream AS for route %q does not expose a registration_endpoint; Dynamic Client Registration is required", routeName)
	}

	redirectURI := m.publicURL + "/upstream/callback/" + routeName
	dcrReq := DCRRequest{
		RedirectURIs:            []string{redirectURI},
		ClientName:              "mcp-gateway/" + routeName,
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	dcrResp, err := RegisterClient(ctx, m.httpClient, meta.RegistrationEndpoint, dcrReq)
	if err != nil {
		return ClientRecord{}, fmt.Errorf("Dynamic Client Registration for route %q: %w", routeName, err)
	}

	record := ClientRecord{
		RouteName:             routeName,
		Issuer:                meta.Issuer,
		AuthorizationEndpoint: meta.AuthorizationEndpoint,
		TokenEndpoint:         meta.TokenEndpoint,
		RegistrationEndpoint:  meta.RegistrationEndpoint,
		ClientID:              dcrResp.ClientID,
		ClientSecret:          dcrResp.ClientSecret,
		RegisteredAt:          time.Now().UTC(),
	}
	if err := m.store.Save(record); err != nil {
		slog.Warn("upstream client store save failed; DCR result will not survive restart",
			"route", routeName, "err", err)
	}
	return record, nil
}

// discoverCached returns AS metadata for routeName, using the in-memory
// cache to avoid repeated network calls for the same route.
func (m *Manager) discoverCached(ctx context.Context, routeName, upstreamOAuth, resourceURL string) (*AuthServerMetadata, error) {
	m.mu.RLock()
	cached, ok := m.cache[routeName]
	m.mu.RUnlock()
	if ok {
		return cached, nil
	}

	var meta *AuthServerMetadata
	var err error
	if strings.EqualFold(upstreamOAuth, "auto") {
		meta, err = DiscoverFromResource(ctx, m.httpClient, resourceURL)
	} else {
		meta, err = DiscoverFromIssuer(ctx, m.httpClient, upstreamOAuth)
	}
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.cache[routeName] = meta
	m.mu.Unlock()
	return meta, nil
}
