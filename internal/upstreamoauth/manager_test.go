package upstreamoauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// newTestManager は一時ファイルストアを使った Manager を返す。
func newTestManager(t *testing.T, publicURL string) *Manager {
	t.Helper()
	dir := t.TempDir()
	store, err := NewFileClientStore(filepath.Join(dir, "upstream_clients.json"))
	if err != nil {
		t.Fatalf("NewFileClientStore: %v", err)
	}
	return NewManager(store, publicURL)
}

// setupASAndDCR は AS metadata と DCR エンドポイントを提供するテストサーバーを返す。
// dcrCalls に DCR リクエスト回数を記録する。
func setupASAndDCR(t *testing.T, clientID string, dcrCalls *atomic.Int32) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(AuthServerMetadata{
				Issuer:                srv.URL,
				AuthorizationEndpoint: srv.URL + "/authorize",
				TokenEndpoint:         srv.URL + "/token",
				RegistrationEndpoint:  srv.URL + "/register",
			})
		case "/register":
			if dcrCalls != nil {
				dcrCalls.Add(1)
			}
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(DCRResponse{
				ClientID:     clientID,
				ClientSecret: "secret-" + clientID,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	return srv
}

func TestManager_EnsureClient_FullFlow(t *testing.T) {
	m := newTestManager(t, "https://gateway.example.com")

	var dcrCalls atomic.Int32
	asSrv := setupASAndDCR(t, "cid-route1", &dcrCalls)
	defer asSrv.Close()

	m.httpClient = asSrv.Client()

	rec, err := m.EnsureClient(context.Background(), "route1", asSrv.URL, "")
	if err != nil {
		t.Fatalf("EnsureClient: %v", err)
	}
	if rec.ClientID != "cid-route1" {
		t.Errorf("ClientID: got %q, want %q", rec.ClientID, "cid-route1")
	}
	if rec.RouteName != "route1" {
		t.Errorf("RouteName: got %q, want %q", rec.RouteName, "route1")
	}
	if dcrCalls.Load() != 1 {
		t.Errorf("DCR calls: got %d, want 1", dcrCalls.Load())
	}
}

func TestManager_EnsureClient_CacheHit(t *testing.T) {
	m := newTestManager(t, "https://gateway.example.com")

	var dcrCalls atomic.Int32
	asSrv := setupASAndDCR(t, "cid-cached", &dcrCalls)
	defer asSrv.Close()

	m.httpClient = asSrv.Client()

	// 1 回目: discovery + DCR
	if _, err := m.EnsureClient(context.Background(), "route-cache", asSrv.URL, ""); err != nil {
		t.Fatalf("EnsureClient (first): %v", err)
	}

	// 2 回目: store から即返却（network call なし）
	if _, err := m.EnsureClient(context.Background(), "route-cache", asSrv.URL, ""); err != nil {
		t.Fatalf("EnsureClient (second): %v", err)
	}

	if dcrCalls.Load() != 1 {
		t.Errorf("DCR calls: got %d, want 1 (second call must use store cache)", dcrCalls.Load())
	}
}

func TestManager_EnsureClient_SkipDCRWhenClientIDExists(t *testing.T) {
	dir := t.TempDir()
	store, err := NewFileClientStore(filepath.Join(dir, "upstream_clients.json"))
	if err != nil {
		t.Fatalf("NewFileClientStore: %v", err)
	}

	// 事前に ClientID を保存しておく
	if err := store.Save(ClientRecord{
		RouteName:             "pre-registered",
		Issuer:                "https://as.example.com",
		AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint:         "https://as.example.com/token",
		ClientID:              "existing-cid",
	}); err != nil {
		t.Fatalf("Save pre-registered: %v", err)
	}

	m := NewManager(store, "https://gateway.example.com")

	var dcrCalls atomic.Int32
	asSrv := setupASAndDCR(t, "new-cid", &dcrCalls)
	defer asSrv.Close()
	m.httpClient = asSrv.Client()

	rec, err := m.EnsureClient(context.Background(), "pre-registered", asSrv.URL, "")
	if err != nil {
		t.Fatalf("EnsureClient: %v", err)
	}
	if rec.ClientID != "existing-cid" {
		t.Errorf("ClientID: got %q, want existing-cid", rec.ClientID)
	}
	if dcrCalls.Load() != 0 {
		t.Errorf("DCR should not be called when client_id already exists, got %d calls", dcrCalls.Load())
	}
}

func TestManager_EnsureClient_MissingRegistrationEndpoint(t *testing.T) {
	m := newTestManager(t, "https://gateway.example.com")

	// registration_endpoint のない AS
	asSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(AuthServerMetadata{
			Issuer:                "https://as.example.com",
			AuthorizationEndpoint: "https://as.example.com/authorize",
			TokenEndpoint:         "https://as.example.com/token",
			// RegistrationEndpoint 欠落
		})
	}))
	defer asSrv.Close()

	m.httpClient = asSrv.Client()

	_, err := m.EnsureClient(context.Background(), "no-dcr-route", asSrv.URL, "")
	if err == nil {
		t.Fatal("expected error for missing registration_endpoint, got nil")
	}
}

func TestManager_EnsureClient_Auto_TwoStep(t *testing.T) {
	m := newTestManager(t, "https://gateway.example.com")

	var asSrv *httptest.Server
	asSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(w).Encode(AuthServerMetadata{
				Issuer:                asSrv.URL,
				AuthorizationEndpoint: asSrv.URL + "/authorize",
				TokenEndpoint:         asSrv.URL + "/token",
				RegistrationEndpoint:  asSrv.URL + "/register",
			})
		case "/register":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(DCRResponse{ClientID: "cid-auto"})
		default:
			http.NotFound(w, r)
		}
	}))
	defer asSrv.Close()

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

	// auto 検索: httpClient は両サーバーに接続できる必要がある（どちらも plain HTTP）
	m.httpClient = prmSrv.Client()

	rec, err := m.EnsureClient(context.Background(), "auto-route", "auto", prmSrv.URL+"/sse")
	if err != nil {
		t.Fatalf("EnsureClient (auto): %v", err)
	}
	if rec.ClientID != "cid-auto" {
		t.Errorf("ClientID: got %q, want cid-auto", rec.ClientID)
	}
}

func TestManager_discoverCached_NoSecondNetworkCall(t *testing.T) {
	m := newTestManager(t, "https://gateway.example.com")

	var discoverCalls atomic.Int32
	asSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		discoverCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/.well-known/oauth-authorization-server" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(AuthServerMetadata{
			Issuer:                "https://as.example.com",
			AuthorizationEndpoint: "https://as.example.com/authorize",
			TokenEndpoint:         "https://as.example.com/token",
			RegistrationEndpoint:  "https://as.example.com/register",
		})
	}))
	defer asSrv.Close()
	m.httpClient = asSrv.Client()

	ctx := context.Background()
	if _, err := m.discoverCached(ctx, "r1", asSrv.URL, ""); err != nil {
		t.Fatalf("discoverCached (first): %v", err)
	}
	callsAfterFirst := discoverCalls.Load()

	if _, err := m.discoverCached(ctx, "r1", asSrv.URL, ""); err != nil {
		t.Fatalf("discoverCached (second): %v", err)
	}
	if discoverCalls.Load() != callsAfterFirst {
		t.Errorf("discovery network call count increased on second call: %d → %d", callsAfterFirst, discoverCalls.Load())
	}
}
