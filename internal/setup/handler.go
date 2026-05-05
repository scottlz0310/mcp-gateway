package setup

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/router"
)

const maxRequestBodyBytes = 16 * 1024 // 16 KB

// Handler serves the first-run setup wizard endpoints.
type Handler struct {
	mgr          *Manager
	appCfg       *appconfig.AppConfig
	cfgPath      string
	km           *appconfig.KeyMaterial
	isHTTPS      func(r *http.Request) bool
	onSuccess    func() // called after successful POST (typically schedules os.Exit)
	envClientID  string
	envSecret    string
	hasEnvRoutes bool
	postMu       sync.Mutex // serializes POST /setup to prevent concurrent token-race
}

// HandlerOption is a functional option for NewHandler.
type HandlerOption func(*Handler)

// WithEnvValues supplies the effective env-derived values so that GET /setup
// reports only genuinely missing fields, and POST /setup can omit fields that
// are already satisfied by env vars.
func WithEnvValues(clientID, secret string, hasRoutes bool) HandlerOption {
	return func(h *Handler) {
		h.envClientID  = clientID
		h.envSecret    = secret
		h.hasEnvRoutes = hasRoutes
	}
}

// NewHandler creates a setup HTTP handler.
//
// cfgPath is the path to config.yaml.
// onSuccess is invoked (in a goroutine) after a successful POST /setup so
// the caller can schedule a clean process exit.
func NewHandler(mgr *Manager, appCfg *appconfig.AppConfig, cfgPath string, km *appconfig.KeyMaterial, onSuccess func(), opts ...HandlerOption) *Handler {
	h := &Handler{
		mgr:       mgr,
		appCfg:    appCfg,
		cfgPath:   cfgPath,
		km:        km,
		isHTTPS:   defaultHTTPSCheck,
		onSuccess: onSuccess,
	}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// RegisterRoutes attaches GET /setup and POST /setup to mux, gated by the
// one-time token supplied as a query parameter (?token=...).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/setup", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.handleGet(w, r)
		case http.MethodPost:
			h.handlePost(w, r)
		default:
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
	})
}

// handleGet returns the list of missing configuration fields for the caller.
func (h *Handler) handleGet(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if err := h.mgr.Validate(token); err != nil {
		writeJSONError(w, tokenErrStatus(err), err.Error())
		return
	}
	missing := h.missingFields()
	writeJSON(w, http.StatusOK, map[string]any{
		"missing": missing,
		"hint":    "POST /setup with JSON body: {\"client_id\",\"client_secret\",\"routes\":[{\"name\",\"prefix\",\"upstream\"}]}",
	})
}

// setupRequest is the JSON body expected for POST /setup.
type setupRequest struct {
	ClientID     string                    `json:"client_id"`
	ClientSecret string                    `json:"client_secret"`
	Routes       []appconfig.RouteConfig   `json:"routes"`
}

// handlePost validates the token, persists the configuration, and schedules
// a clean shutdown so the supervisor can restart in normal mode.
//
// The postMu mutex ensures that concurrent POSTs are serialized so that only
// one request can pass Validate() and proceed to Consume() at a time,
// preserving the single-use token semantics.
func (h *Handler) handlePost(w http.ResponseWriter, r *http.Request) {
	h.postMu.Lock()
	defer h.postMu.Unlock()

	if !h.isHTTPS(r) {
		// Warn but don't block — /setup may be served on localhost or via a
		// TLS-terminating proxy.  We log a warning so operators notice.
		slog.Warn("setup wizard POST received over plain HTTP; ensure TLS in production")
	}

	token := r.URL.Query().Get("token")
	if err := h.mgr.Validate(token); err != nil {
		writeJSONError(w, tokenErrStatus(err), err.Error())
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)
	var req setupRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid JSON: "+err.Error())
		return
	}
	// Reject bodies containing more than one top-level JSON value.
	var extra json.RawMessage
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSONError(w, http.StatusUnprocessableEntity, "request body must contain exactly one JSON object")
		return
	}

	// Only require fields that are not already satisfied by effective config.
	needClientID := strings.TrimSpace(h.envClientID) == "" && strings.TrimSpace(h.appCfg.Auth.GitHubClientID) == ""
	needSecret   := strings.TrimSpace(h.envSecret) == "" && strings.TrimSpace(h.appCfg.Auth.GitHubClientSecret) == ""
	needRoutes   := !h.hasEnvRoutes && len(h.appCfg.Routes) == 0

	if needClientID && strings.TrimSpace(req.ClientID) == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "client_id is required")
		return
	}
	if needSecret && strings.TrimSpace(req.ClientSecret) == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "client_secret is required")
		return
	}
	if needRoutes && len(req.Routes) == 0 {
		writeJSONError(w, http.StatusUnprocessableEntity, "at least one route is required")
		return
	}

	// Validate provided route list by attempting a parse.
	if len(req.Routes) > 0 {
		if _, err := router.ParseFromConfig(req.Routes); err != nil {
			writeJSONError(w, http.StatusUnprocessableEntity, "invalid route: "+err.Error())
			return
		}
	}

	// Encrypt new secret before persisting (only if provided).
	var encSecret string
	if strings.TrimSpace(req.ClientSecret) != "" {
		var err error
		encSecret, err = appconfig.EncryptField(h.km, req.ClientSecret)
		if err != nil {
			writeJSONError(w, http.StatusInternalServerError, "failed to encrypt secret: "+err.Error())
			return
		}
	}

	// Save previous in-memory state for rollback on SaveConfig failure.
	prevClientID     := h.appCfg.Auth.GitHubClientID
	prevClientSecret := h.appCfg.Auth.GitHubClientSecret
	prevRoutes       := h.appCfg.Routes
	prevCompleted    := h.appCfg.Setup.Completed

	// Apply changes to in-memory config (only for fields provided in the request).
	if strings.TrimSpace(req.ClientID) != "" {
		h.appCfg.Auth.GitHubClientID = req.ClientID
	}
	if encSecret != "" {
		h.appCfg.Auth.GitHubClientSecret = encSecret
	}
	if len(req.Routes) > 0 {
		h.appCfg.Routes = req.Routes
	}
	h.appCfg.Setup.Completed = true

	if err := appconfig.SaveConfig(h.cfgPath, h.appCfg); err != nil {
		// Restore previous in-memory state.
		h.appCfg.Auth.GitHubClientID     = prevClientID
		h.appCfg.Auth.GitHubClientSecret = prevClientSecret
		h.appCfg.Routes                  = prevRoutes
		h.appCfg.Setup.Completed         = prevCompleted
		writeJSONError(w, http.StatusInternalServerError, "failed to save config: "+err.Error())
		return
	}

	// Consume the token so no further /setup calls succeed.
	h.mgr.Consume()

	writeJSON(w, http.StatusOK, map[string]any{
		"saved":            true,
		"restart_required": true,
	})

	// Schedule clean shutdown after the response is flushed.
	go func() {
		time.Sleep(200 * time.Millisecond)
		h.onSuccess()
	}()
}

// UnconfiguredHandler returns a 503 JSON response for every request, directing
// operators to the setup URL.  Used during wizard mode for all non-/setup routes.
func UnconfiguredHandler(setupURL string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":     "setup_required",
			"setup_url": setupURL,
		})
	})
}

// WaitForShutdown serves mux until ctx is cancelled.
func WaitForShutdown(ctx context.Context, srv *http.Server) error {
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	return srv.ListenAndServe()
}

// --- helpers ---

// missingFields returns the configuration fields that are not satisfied by
// either env-derived values or the current appCfg.
func (h *Handler) missingFields() []string {
	var missing []string
	if strings.TrimSpace(h.envClientID) == "" && strings.TrimSpace(h.appCfg.Auth.GitHubClientID) == "" {
		missing = append(missing, "client_id")
	}
	if strings.TrimSpace(h.envSecret) == "" && strings.TrimSpace(h.appCfg.Auth.GitHubClientSecret) == "" {
		missing = append(missing, "client_secret")
	}
	if !h.hasEnvRoutes && len(h.appCfg.Routes) == 0 {
		missing = append(missing, "routes")
	}
	return missing
}

func tokenErrStatus(err error) int {
	switch {
	case errors.Is(err, ErrTokenExpired):
		return http.StatusRequestTimeout // 408
	case errors.Is(err, ErrAlreadyConfigured):
		return http.StatusConflict // 409
	default:
		return http.StatusUnauthorized // 401
	}
}

func defaultHTTPSCheck(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
