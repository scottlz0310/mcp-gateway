package upstreamoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterClient_201Created(t *testing.T) {
	want := DCRResponse{
		ClientID:     "client-id-abc",
		ClientSecret: "secret-xyz",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	req := DCRRequest{
		RedirectURIs:            []string{"https://gateway.example.com/callback"},
		ClientName:              "mcp-gateway/test-route",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}
	got, err := RegisterClient(context.Background(), srv.Client(), srv.URL+"/register", req)
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if got.ClientID != want.ClientID {
		t.Errorf("ClientID: got %q, want %q", got.ClientID, want.ClientID)
	}
	if got.ClientSecret != want.ClientSecret {
		t.Errorf("ClientSecret: got %q, want %q", got.ClientSecret, want.ClientSecret)
	}
}

func TestRegisterClient_200OK(t *testing.T) {
	want := DCRResponse{ClientID: "cid-200"}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(want)
	}))
	defer srv.Close()

	got, err := RegisterClient(context.Background(), srv.Client(), srv.URL+"/register", DCRRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err != nil {
		t.Fatalf("RegisterClient: %v", err)
	}
	if got.ClientID != want.ClientID {
		t.Errorf("ClientID: got %q, want %q", got.ClientID, want.ClientID)
	}
}

func TestRegisterClient_Non2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer srv.Close()

	_, err := RegisterClient(context.Background(), srv.Client(), srv.URL+"/register", DCRRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for non-2xx response, got nil")
	}
}

func TestRegisterClient_MissingClientID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		// client_id が欠落したレスポンス
		_ = json.NewEncoder(w).Encode(map[string]string{"client_secret": "secret"})
	}))
	defer srv.Close()

	_, err := RegisterClient(context.Background(), srv.Client(), srv.URL+"/register", DCRRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for missing client_id, got nil")
	}
}

func TestRegisterClient_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := RegisterClient(context.Background(), srv.Client(), srv.URL+"/register", DCRRequest{
		RedirectURIs: []string{"https://example.com/callback"},
	})
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}
