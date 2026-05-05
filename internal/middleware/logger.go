package middleware

import (
	"bufio"
	"context"
	"io"
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
// it supports connection hijacking (e.g. for WebSocket upgrades). On success
// the status is recorded as 101 Switching Protocols so that the access log
// reflects the real protocol-upgrade response rather than the default 200.
func (sw *statusWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := sw.ResponseWriter.(http.Hijacker); ok {
		conn, rw, err := h.Hijack()
		if err == nil && !sw.wrote {
			sw.status = http.StatusSwitchingProtocols
			sw.wrote = true
		}
		return conn, rw, err
	}
	return nil, nil, http.ErrNotSupported
}

// ReadFrom implements io.ReaderFrom to preserve the optimised ReadFrom fast
// path (e.g. sendfile via net.Conn) when the underlying ResponseWriter supports
// it. Without this, httputil.ReverseProxy falls back to a generic buffered copy
// which adds avoidable CPU and memory overhead for large or streaming responses.
func (sw *statusWriter) ReadFrom(src io.Reader) (int64, error) {
	if !sw.wrote {
		sw.status = http.StatusOK
		sw.wrote = true
	}
	if rf, ok := sw.ResponseWriter.(io.ReaderFrom); ok {
		return rf.ReadFrom(src)
	}
	return io.Copy(sw.ResponseWriter, src)
}
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
//
// The log is written inside a deferred function that also recovers panics:
// if a downstream handler panics before writing any headers the status is
// set to 500 and the access log is emitted before re-panicking so that
// net/http's own recover can send a 500 response to the client.
func Logger() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w}
			defer func() {
				p := recover()
				// Downstream panicked before writing headers: record 500 so the
				// access log is not misleadingly shown as 200 OK.
				if p != nil && !sw.wrote {
					sw.status = http.StatusInternalServerError
					sw.wrote = true
				}
				latency := time.Since(start).Milliseconds()
				logFuncForStatus(sw.statusCode())(r.Context(), "http request",
					"method", r.Method,
					"path", r.URL.Path,
					"status", sw.statusCode(),
					"latency_ms", latency,
					"remote_addr", r.RemoteAddr,
				)
				if p != nil {
					panic(p) // re-panic so net/http can recover and send 500
				}
			}()
			next.ServeHTTP(sw, r)
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
