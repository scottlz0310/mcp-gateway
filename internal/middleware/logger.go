package middleware

import (
	"context"
	"log/slog"
	"net/http"
	"time"
)

// statusWriter wraps http.ResponseWriter to capture the written HTTP status
// code. It implements Unwrap so that http.NewResponseController can reach the
// underlying writer and use its optional interfaces (Flush, Hijack, etc.),
// preserving streaming behaviour through the Logger middleware.
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

// Unwrap returns the underlying ResponseWriter so that http.ResponseController
// and direct Flusher/Hijacker type-assertions continue to work through the wrapper.
func (sw *statusWriter) Unwrap() http.ResponseWriter {
	return sw.ResponseWriter
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
//	4xx → Warn
//	2xx/3xx → Info
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
	switch {
	case status >= 500:
		return slog.ErrorContext
	case status >= 400:
		return slog.WarnContext
	default:
		return slog.InfoContext
	}
}
