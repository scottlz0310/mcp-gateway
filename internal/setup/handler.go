package setup

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	appconfig "github.com/scottlz0310/mcp-gateway/internal/config"
	"github.com/scottlz0310/mcp-gateway/internal/router"
)

// Handler serves the first-run setup wizard endpoints.
type Handler struct {
	mgr       *Manager
	appCfg    *appconfig.AppConfig
	cfgPath   string
	km        *appconfig.KeyMaterial
	isHTTPS   func(r *http.Request) bool
	onSuccess func() // called after successful POST (typically schedules os.Exit)
}

// NewHandler creates a setup HTTP handler.
//
// cfgPath is the path to config.yaml.
// onSuccess is invoked (in a goroutine) after a successful POST /setup so
// the caller can schedule a clean process exit.
func NewHandler(mgr *Manager, appCfg *appconfig.AppConfig, cfgPath string, km *appconfig.KeyMaterial, onSuccess func()) *Handler {
	return &Handler{
		mgr:       mgr,
		appCfg:    appCfg,
		cfgPath:   cfgPath,
		km:        km,
		isHTTPS:   defaultHTTPSCheck,
		onSuccess: onSuccess,
	}
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
func (h *Handler) handlePost(w http.ResponseWriter, r *http.Request) {
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

	var req setupRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid JSON: "+err.Error())
		return
	}

	if strings.TrimSpace(req.ClientID) == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "client_id is required")
		return
	}
	if strings.TrimSpace(req.ClientSecret) == "" {
		writeJSONError(w, http.StatusUnprocessableEntity, "client_secret is required")
		return
	}
	if len(req.Routes) == 0 {
		writeJSONError(w, http.StatusUnprocessableEntity, "at least one route is required")
		return
	}

	// Validate route list by attempting a parse.
	if _, err := router.ParseFromConfig(req.Routes); err != nil {
		writeJSONError(w, http.StatusUnprocessableEntity, "invalid route: "+err.Error())
		return
	}

	// Encrypt secret before persisting.
	encSecret, err := appconfig.EncryptField(h.km, req.ClientSecret)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to encrypt secret: "+err.Error())
		return
	}

	// Apply changes to the in-memory config.
	h.appCfg.Auth.GitHubClientID = req.ClientID
	h.appCfg.Auth.GitHubClientSecret = encSecret
	h.appCfg.Routes = req.Routes
	h.appCfg.Setup.Completed = true

	if err := appconfig.SaveConfig(h.cfgPath, h.appCfg); err != nil {
		// Attempt rollback of in-memory changes.
		h.appCfg.Auth.GitHubClientID = ""
		h.appCfg.Auth.GitHubClientSecret = ""
		h.appCfg.Routes = nil
		h.appCfg.Setup.Completed = false
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

func (h *Handler) missingFields() []string {
	var missing []string
	if h.appCfg.Auth.GitHubClientID == "" {
		missing = append(missing, "client_id")
	}
	if h.appCfg.Auth.GitHubClientSecret == "" {
		missing = append(missing, "client_secret")
	}
	if len(h.appCfg.Routes) == 0 {
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
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}
