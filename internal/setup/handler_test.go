package setup_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/setup"
)

func newTestKM(t *testing.T) *appconfig.KeyMaterial {
	t.Helper()
	km, err := appconfig.LoadKey(filepath.Join(t.TempDir(), "gateway.key"), nil)
	if err != nil {
		t.Fatalf("LoadKey: %v", err)
	}
	return km
}

func TestHandlerGet_ValidToken(t *testing.T) {
	mgr, _ := setup.New()
	cfg := &appconfig.AppConfig{}
	km := newTestKM(t)
	h := setup.NewHandler(mgr, cfg, "config.yaml", km, func() {})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/setup?token="+mgr.Token(), nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /setup status = %d, want 200", rec.Code)
	}
}

func TestHandlerGet_InvalidToken(t *testing.T) {
	mgr, _ := setup.New()
	cfg := &appconfig.AppConfig{}
	km := newTestKM(t)
	h := setup.NewHandler(mgr, cfg, "config.yaml", km, func() {})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/setup?token=badtoken", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /setup with bad token status = %d, want 401", rec.Code)
	}
}

func TestHandlerPost_Success(t *testing.T) {
	mgr, _ := setup.New()
	cfg := &appconfig.AppConfig{}
	km := newTestKM(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yaml")

	called := make(chan struct{}, 1)
	h := setup.NewHandler(mgr, cfg, cfgPath, km, func() { called <- struct{}{} })

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := map[string]any{
		"client_id":     "test-client",
		"client_secret": "test-secret",
		"routes": []map[string]any{
			{"name": "mcp", "prefix": "/mcp", "upstream": "http://upstream:8080"},
		},
	}
	b, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/setup?token="+mgr.Token(), bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /setup status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp["saved"] != true {
		t.Errorf("saved = %v, want true", resp["saved"])
	}
	if resp["restart_required"] != true {
		t.Errorf("restart_required = %v, want true", resp["restart_required"])
	}

	// Verify config was written and setup.completed is true.
	saved, err := appconfig.LoadConfig(cfgPath)
	if err != nil {
		t.Fatalf("LoadConfig after POST: %v", err)
	}
	if saved.Auth.GitHubClientID != "test-client" {
		t.Errorf("client_id = %q, want test-client", saved.Auth.GitHubClientID)
	}
	if !saved.Setup.Completed {
		t.Error("setup.completed = false, want true")
	}

	// onSuccess should be called (with delay).
	select {
	case <-called:
		// ok
	case <-time.After(5 * time.Second):
		t.Fatal("onSuccess was not called within 5 seconds")
	}
}

func TestHandlerPost_MissingClientID(t *testing.T) {
	mgr, _ := setup.New()
	cfg := &appconfig.AppConfig{}
	km := newTestKM(t)
	h := setup.NewHandler(mgr, cfg, "config.yaml", km, func() {})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"client_secret":"s","routes":[{"name":"a","prefix":"/mcp","upstream":"http://up:8080"}]}`
	req := httptest.NewRequest(http.MethodPost, "/setup?token="+mgr.Token(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
}

func TestHandlerPost_NoRoutes(t *testing.T) {
	mgr, _ := setup.New()
	cfg := &appconfig.AppConfig{}
	km := newTestKM(t)
	h := setup.NewHandler(mgr, cfg, "config.yaml", km, func() {})

	mux := http.NewServeMux()
	h.RegisterRoutes(mux)

	body := `{"client_id":"id","client_secret":"s","routes":[]}`
	req := httptest.NewRequest(http.MethodPost, "/setup?token="+mgr.Token(), strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
}

func TestUnconfiguredHandler(t *testing.T) {
	h := setup.UnconfiguredHandler("http://localhost:8080/setup?token=tok")
	req := httptest.NewRequest(http.MethodGet, "/mcp/anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", rec.Code)
	}

	var resp map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp["error"] != "setup_required" {
		t.Errorf("error = %q, want setup_required", resp["error"])
	}
}
