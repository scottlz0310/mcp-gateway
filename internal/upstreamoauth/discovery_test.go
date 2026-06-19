package upstreamoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBuildPRMURL(t *testing.T) {
	tests := []struct {
		resourceURL string
		want        string
	}{
		{"https://mcp.example.com/sse", "https://mcp.example.com/.well-known/oauth-protected-resource/sse"},
		{"https://mcp.example.com/", "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com", "https://mcp.example.com/.well-known/oauth-protected-resource"},
		{"https://mcp.example.com/v1/mcp", "https://mcp.example.com/.well-known/oauth-protected-resource/v1/mcp"},
	}
	for _, tc := range tests {
		t.Run(tc.resourceURL, func(t *testing.T) {
			got, err := buildPRMURL(tc.resourceURL)
			if err != nil {
				t.Fatalf("buildPRMURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBuildASMetaURL(t *testing.T) {
	tests := []struct {
		issuerURL string
		want      string
	}{
		{"https://example.com", "https://example.com/.well-known/oauth-authorization-server"},
		{"https://example.com/", "https://example.com/.well-known/oauth-authorization-server"},
		{"https://example.com/tenant1", "https://example.com/.well-known/oauth-authorization-server/tenant1"},
	}
	for _, tc := range tests {
		t.Run(tc.issuerURL, func(t *testing.T) {
			got, err := buildASMetaURL(tc.issuerURL)
			if err != nil {
				t.Fatalf("buildASMetaURL: %v", err)
			}
			if got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestDiscoverFromIssuer(t *testing.T) {
	asMeta := AuthServerMetadata{
		Issuer:                "https://as.example.com",
		AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint:         "https://as.example.com/token",
		RegistrationEndpoint:  "https://as.example.com/register",
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(asMeta)
	}))
	defer srv.Close()

	client := srv.Client()
	meta, err := DiscoverFromIssuer(context.Background(), client, srv.URL)
	if err != nil {
		t.Fatalf("DiscoverFromIssuer: %v", err)
	}
	if meta.Issuer != asMeta.Issuer {
		t.Errorf("Issuer: got %q, want %q", meta.Issuer, asMeta.Issuer)
	}
	if meta.RegistrationEndpoint != asMeta.RegistrationEndpoint {
		t.Errorf("RegistrationEndpoint: got %q, want %q", meta.RegistrationEndpoint, asMeta.RegistrationEndpoint)
	}
}

func TestDiscoverFromIssuer_MissingRequiredFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// issuer のみ — authorization_endpoint と token_endpoint が欠落
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": "https://as.example.com"})
	}))
	defer srv.Close()

	_, err := DiscoverFromIssuer(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for missing required fields, got nil")
	}
}

func TestDiscoverFromIssuer_Non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	_, err := DiscoverFromIssuer(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

func TestDiscoverFromIssuer_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("not json"))
	}))
	defer srv.Close()

	_, err := DiscoverFromIssuer(context.Background(), srv.Client(), srv.URL)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestDiscoverFromResource_TwoStep(t *testing.T) {
	// asSrv: RFC 8414 Authorization Server Metadata endpoint
	asSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// asSrv.URL is not accessible here (closure issue) so we hardcode stable fields.
		_ = json.NewEncoder(w).Encode(AuthServerMetadata{
			Issuer:                "https://as.example.com",
			AuthorizationEndpoint: "https://as.example.com/authorize",
			TokenEndpoint:         "https://as.example.com/token",
			RegistrationEndpoint:  "https://as.example.com/register",
		})
	}))
	defer asSrv.Close()

	// prmSrv: RFC 9728 Protected Resource Metadata endpoint → points to asSrv
	var prmSrv *httptest.Server
	prmSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-protected-resource/sse" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
			Resource:             prmSrv.URL + "/sse",
			AuthorizationServers: []string{asSrv.URL},
		})
	}))
	defer prmSrv.Close()

	meta, err := DiscoverFromResource(context.Background(), prmSrv.Client(), prmSrv.URL+"/sse")
	if err != nil {
		t.Fatalf("DiscoverFromResource: %v", err)
	}
	if meta.AuthorizationEndpoint != "https://as.example.com/authorize" {
		t.Errorf("AuthorizationEndpoint: got %q", meta.AuthorizationEndpoint)
	}
	if meta.RegistrationEndpoint != "https://as.example.com/register" {
		t.Errorf("RegistrationEndpoint: got %q", meta.RegistrationEndpoint)
	}
}

func TestDiscoverFromResource_NoAuthServers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(ProtectedResourceMetadata{
			Resource:             "https://mcp.example.com/sse",
			AuthorizationServers: []string{},
		})
	}))
	defer srv.Close()

	_, err := DiscoverFromResource(context.Background(), srv.Client(), srv.URL+"/sse")
	if err == nil {
		t.Fatal("expected error for empty authorization_servers, got nil")
	}
}

func TestDiscoverFromResource_PRMFetchFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, err := DiscoverFromResource(context.Background(), srv.Client(), srv.URL+"/sse")
	if err == nil {
		t.Fatal("expected error for PRM fetch failure, got nil")
	}
}
