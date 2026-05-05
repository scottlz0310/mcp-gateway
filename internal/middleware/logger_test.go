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
	if entry["level"] != "INFO" {
		t.Errorf("level: got %q, want INFO", entry["level"])
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

func TestStatusWriterFlush(t *testing.T) {
	// httptest.ResponseRecorder implements http.Flusher, so Flush() must be
	// forwarded without panicking and must set the Flushed flag.
	inner := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: inner}

	// statusWriter itself must satisfy http.Flusher via direct type assertion.
	flusher, ok := any(sw).(http.Flusher)
	if !ok {
		t.Fatal("statusWriter does not implement http.Flusher")
	}
	flusher.Flush()
	if !inner.Flushed {
		t.Error("Flush did not propagate to underlying ResponseRecorder")
	}
}

func TestStatusWriterHijackNotSupported(t *testing.T) {
	// httptest.ResponseRecorder does NOT implement http.Hijacker, so Hijack()
	// must return http.ErrNotSupported and statusWriter must still satisfy the
	// http.Hijacker interface via direct type assertion.
	inner := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: inner}

	hijacker, ok := any(sw).(http.Hijacker)
	if !ok {
		t.Fatal("statusWriter does not implement http.Hijacker")
	}
	conn, rw, err := hijacker.Hijack()
	if err == nil {
		t.Error("expected error from Hijack when underlying writer does not support it")
	}
	if conn != nil || rw != nil {
		t.Error("Hijack should return nil conn and rw on error")
	}
}

func TestLoggerPanic(t *testing.T) {
	// Even if the downstream handler panics, the deferred log line must still
	// be emitted (net/http recovers the panic after deferred functions run).
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	h := Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("simulated handler panic")
	}))
	r := httptest.NewRequest(http.MethodGet, "/crash", nil)
	w := httptest.NewRecorder()

	func() {
		defer func() { recover() }() //nolint:errcheck
		h.ServeHTTP(w, r)
	}()

	if buf.Len() == 0 {
		t.Error("expected a log line even after handler panic, got none")
	}
	entry := parseLastLog(t, &buf)
	if entry["path"] != "/crash" {
		t.Errorf("path: got %v, want /crash", entry["path"])
	}
}
