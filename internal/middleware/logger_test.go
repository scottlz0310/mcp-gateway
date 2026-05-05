package middleware

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

// captureLogs redirects the default slog logger to a buffer and returns a
// function that restores the original logger (suitable for t.Cleanup).
func captureLogs(t *testing.T, buf *bytes.Buffer) func() {
	t.Helper()
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	return func() { slog.SetDefault(old) }
}

// parseLastLog parses the last complete JSON line from buf as a map.
func parseLastLog(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	lines := bytes.Split(bytes.TrimRight(buf.Bytes(), "\n"), []byte("\n"))
	last := lines[len(lines)-1]
	var m map[string]any
	if err := json.Unmarshal(last, &m); err != nil {
		t.Fatalf("failed to parse log line %q: %v", last, err)
	}
	return m
}

func TestLoggerImplicit200(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	r := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	if entry["level"] != "INFO" {
		t.Errorf("level: got %q, want INFO", entry["level"])
	}
	if entry["status"] != float64(200) {
		t.Errorf("status: got %v, want 200", entry["status"])
	}
	if entry["method"] != "GET" {
		t.Errorf("method: got %v, want GET", entry["method"])
	}
	if entry["path"] != "/health" {
		t.Errorf("path: got %v, want /health", entry["path"])
	}
	if _, ok := entry["latency_ms"]; !ok {
		t.Error("latency_ms field missing")
	}
}

func TestLoggerExplicit200(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodPost, "/token", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	if entry["level"] != "INFO" {
		t.Errorf("level: got %q, want INFO", entry["level"])
	}
	if entry["status"] != float64(200) {
		t.Errorf("status: got %v, want 200", entry["status"])
	}
}

func TestLogger4xx(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	if entry["level"] != "WARN" {
		t.Errorf("level: got %q, want WARN", entry["level"])
	}
	if entry["status"] != float64(401) {
		t.Errorf("status: got %v, want 401", entry["status"])
	}
}

func TestLogger5xx(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	r := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	if entry["level"] != "ERROR" {
		t.Errorf("level: got %q, want ERROR", entry["level"])
	}
	if entry["status"] != float64(503) {
		t.Errorf("status: got %v, want 503", entry["status"])
	}
}

func TestLoggerFieldsPresent(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	r := httptest.NewRequest(http.MethodGet, "/mcp/v1/resource", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	for _, field := range []string{"method", "path", "status", "latency_ms", "remote_addr"} {
		if _, ok := entry[field]; !ok {
			t.Errorf("expected field %q to be present in log entry", field)
		}
	}
}

func TestLoggerUnwrap(t *testing.T) {
	inner := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: inner}
	if sw.Unwrap() != inner {
		t.Error("Unwrap should return the underlying ResponseWriter")
	}
}
