package middleware

import (
	"bufio"
	"context"
	"log/slog"
	"net"
	"net/http"
	"time"
)

// statusWriter wraps http.ResponseWriter to capture the written HTTP status
// code. It explicitly implements http.Flusher and http.Hijacker by delegating
// to the underlying writer, so that both direct type-assertions and
// http.NewResponseController can reach those capabilities through the wrapper.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (sw *statusWriter) WriteHeader(code int) {
	if !sw.wrote {
		sw.status = code
		sw.wrote = true
	}
	sw.ResponseWriter.WriteHeader(code)
}

func (sw *statusWriter) Write(b []byte) (int, error) {
	if !sw.wrote {
		sw.status = http.StatusOK
		sw.wrote = true
	}
	return sw.ResponseWriter.Write(b)
}

// Unwrap returns the underlying ResponseWriter so http.NewResponseController
// can find optional interfaces beyond Flusher and Hijacker.
func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
}

// Flush implements http.Flusher, delegating to the underlying writer when
// it supports flushing (e.g. for Server-Sent Events or chunked responses).
func (sw *statusWriter) Flush() {
	if f, ok := sw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack implements http.Hijacker, delegating to the underlying writer when
// it supports connection hijacking (e.g. for WebSocket upgrades).
func (sw *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := sw.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// statusCode returns the captured status, defaulting to 200 when no status was
// explicitly written (implicit 200 OK from the first Write).
func (sw *statusWriter) statusCode() int {
	if !sw.wrote {
		return http.StatusOK
	}
	return sw.status
}

// Logger returns a middleware that emits one structured log line per HTTP
// request containing: method, path, status, latency_ms, remote_addr.
//
// Log level is chosen by status range:
//
//	5xx → Error
//	2xx/3xx/4xx → Info
func Logger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			next.ServeHTTP(sw, r)
			latency := time.Since(start).Milliseconds()
			logFn := logFuncForStatus(sw.statusCode())
			logFn(r.Context(), "http request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", sw.statusCode(),
				"latency_ms", latency,
				"remote_addr", r.RemoteAddr,
			)
		})
	}
}

type logFunc func(ctx context.Context, msg string, args ...any)

func logFuncForStatus(status int) logFunc {
	if status >= 500 {
		return slog.ErrorContext
	}
	return slog.InfoContext
}
