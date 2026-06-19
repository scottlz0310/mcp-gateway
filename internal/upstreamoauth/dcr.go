package upstreamoauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// DCRRequest is the RFC 7591 §2 client metadata registration request body.
type DCRRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

// DCRResponse is the RFC 7591 §3.2.1 client information response.
type DCRResponse struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
}

// RegisterClient performs RFC 7591 Dynamic Client Registration by posting req
// to registrationEndpoint. Both 200 OK and 201 Created are accepted per
// common server implementations.
func RegisterClient(ctx context.Context, client *http.Client, registrationEndpoint string, req DCRRequest) (*DCRResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling DCR request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("creating DCR request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", registrationEndpoint, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DCR at %s: unexpected status %d", registrationEndpoint, resp.StatusCode)
	}
	var dcrResp DCRResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcrResp); err != nil {
		return nil, fmt.Errorf("decoding DCR response from %s: %w", registrationEndpoint, err)
	}
	if dcrResp.ClientID == "" {
		return nil, fmt.Errorf("DCR response from %s missing required client_id", registrationEndpoint)
	}
	return &dcrResp, nil
}
