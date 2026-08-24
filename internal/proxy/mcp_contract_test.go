package proxy

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/middleware"
)

// MCP negotiation contract tests (issue #216).
//
// The gateway is a reverse proxy and an auth boundary; it is not an MCP server.
// It must never synthesize, absorb or rewrite anything the MCP protocol uses to
// negotiate a connection: the MCP-Protocol-Version header, the server/discover
// JSON-RPC exchange, HTTP status codes, or the long-lived SSE stream that
// subscriptions/listen returns under MCP 2026-07-28.
//
// These tests pin that transparency so that a future change to the proxy layer
// cannot silently break negotiation for either the modern stateless protocol or
// the legacy Mcp-Session-Id routing that predates it.

// contractEnv is a gateway server in front of an upstream server, with the
// authenticated identity already established (as the auth middleware would).
type contractEnv struct {
	gateway     *httptest.Server
	invalidator *mockInvalidator
}

func newContractEnv(t *testing.T, upstreamHandler http.Handler) *contractEnv {
	t.Helper()

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}

	inv := &mockInvalidator{}
	h := NewHandler(u, inv, "", "", nil)
	gateway := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx := context.WithValue(r.Context(), middleware.ContextKeyIdentity, "alice")
		ctx = context.WithValue(ctx, middleware.ContextKeyToken, "gateway-client-token")
		h.ServeHTTP(w, r.WithContext(ctx))
	}))
	t.Cleanup(gateway.Close)

	return &contractEnv{gateway: gateway, invalidator: inv}
}

func (e *contractEnv) do(t *testing.T, req *http.Request) *http.Response {
	t.Helper()
	resp, err := e.gateway.Client().Do(req)
	if err != nil {
		t.Fatalf("gateway request: %v", err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// TestMCPNegotiationHeadersPassThrough verifies that the headers MCP uses to
// negotiate a protocol version survive both directions unchanged. The SDKs
// reject a mismatch between MCP-Protocol-Version and _meta.protocolVersion with
// CodeHeaderMismatch, so any rewrite here breaks the connection outright.
func TestMCPNegotiationHeadersPassThrough(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name:    "modern stateless negotiation",
			headers: map[string]string{"MCP-Protocol-Version": "2026-07-28"},
		},
		{
			name: "legacy stateful negotiation",
			headers: map[string]string{
				"MCP-Protocol-Version": "2025-11-25",
				"Mcp-Session-Id":       "legacy-session-abc123",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUpstream := make(http.Header)
			env := newContractEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotUpstream = r.Header.Clone()
				for name, value := range tt.headers {
					w.Header().Set(name, value)
				}
				w.WriteHeader(http.StatusOK)
			}))

			req, err := http.NewRequest(http.MethodPost, env.gateway.URL+"/mcp", strings.NewReader("{}"))
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			for name, value := range tt.headers {
				req.Header.Set(name, value)
			}

			resp := env.do(t, req)

			for name, want := range tt.headers {
				if got := gotUpstream.Get(name); got != want {
					t.Errorf("upstream request %s: got %q, want %q", name, got, want)
				}
				if got := resp.Header.Get(name); got != want {
					t.Errorf("client response %s: got %q, want %q", name, got, want)
				}
			}
		})
	}
}

// TestGatewayDoesNotMintSession verifies that the gateway neither invents an
// Mcp-Session-Id nor requires one. MCP 2026-07-28 has no protocol-level
// session, so a gateway that minted one would attach state to a stateless
// protocol and imply a session affinity requirement that does not exist.
func TestGatewayDoesNotMintSession(t *testing.T) {
	var upstreamCalls int
	sessionSeenUpstream := false
	env := newContractEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls++
		if r.Header.Get("Mcp-Session-Id") != "" {
			sessionSeenUpstream = true
		}
		w.WriteHeader(http.StatusOK)
	}))

	// Two independent requests, neither carrying a session: both must reach the
	// upstream and neither may come back with a session header.
	for i := range 2 {
		req, err := http.NewRequest(http.MethodPost, env.gateway.URL+"/mcp", strings.NewReader("{}"))
		if err != nil {
			t.Fatalf("build request %d: %v", i, err)
		}
		resp := env.do(t, req)
		if got := resp.Header.Get("Mcp-Session-Id"); got != "" {
			t.Errorf("request %d: gateway minted Mcp-Session-Id %q", i, got)
		}
	}

	if upstreamCalls != 2 {
		t.Errorf("upstream calls: got %d, want 2", upstreamCalls)
	}
	if sessionSeenUpstream {
		t.Error("gateway added Mcp-Session-Id to a stateless request")
	}
}

// TestServerDiscoverPassThrough verifies that the JSON-RPC body, the request ID
// and the HTTP status of the negotiation exchange are preserved end to end.
// The gateway must not answer server/discover itself, and must not normalize an
// upstream negotiation failure into a different status.
func TestServerDiscoverPassThrough(t *testing.T) {
	discoverRequest := `{"jsonrpc":"2.0","id":1,"method":"server/discover","params":{"_meta":{"protocolVersion":"2026-07-28"}}}`

	tests := []struct {
		name           string
		method         string
		requestBody    string
		upstreamStatus int
		upstreamBody   string
	}{
		{
			name:           "discover success",
			method:         http.MethodPost,
			requestBody:    discoverRequest,
			upstreamStatus: http.StatusOK,
			upstreamBody:   `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2026-07-28","capabilities":{"resources":{"subscribe":true}}}}`,
		},
		{
			name:           "unsupported protocol version",
			method:         http.MethodPost,
			requestBody:    discoverRequest,
			upstreamStatus: http.StatusBadRequest,
			upstreamBody:   `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported protocol version"}}`,
		},
		{
			name:           "GET rejected by upstream",
			method:         http.MethodGet,
			upstreamStatus: http.StatusMethodNotAllowed,
			upstreamBody:   `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"method not allowed"}}`,
		},
		{
			name:           "DELETE rejected by upstream",
			method:         http.MethodDelete,
			upstreamStatus: http.StatusMethodNotAllowed,
			upstreamBody:   `{"jsonrpc":"2.0","id":null,"error":{"code":-32000,"message":"method not allowed"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotBody string
			env := newContractEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Errorf("read upstream request body: %v", err)
				}
				gotBody = string(body)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tt.upstreamStatus)
				_, _ = io.WriteString(w, tt.upstreamBody)
			}))

			var body io.Reader
			if tt.requestBody != "" {
				body = strings.NewReader(tt.requestBody)
			}
			req, err := http.NewRequest(tt.method, env.gateway.URL+"/mcp", body)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			req.Header.Set("MCP-Protocol-Version", "2026-07-28")

			resp := env.do(t, req)
			gotResponseBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read gateway response body: %v", err)
			}

			if gotMethod != tt.method {
				t.Errorf("upstream method: got %q, want %q", gotMethod, tt.method)
			}
			if gotBody != tt.requestBody {
				t.Errorf("upstream request body: got %q, want %q", gotBody, tt.requestBody)
			}
			if resp.StatusCode != tt.upstreamStatus {
				t.Errorf("status: got %d, want %d", resp.StatusCode, tt.upstreamStatus)
			}
			if string(gotResponseBody) != tt.upstreamBody {
				t.Errorf("response body: got %q, want %q", gotResponseBody, tt.upstreamBody)
			}
		})
	}
}

// TestProxyStreamsSSEWithoutBuffering verifies that a long-lived SSE stream is
// forwarded chunk by chunk instead of being accumulated. Under MCP 2026-07-28
// the response to subscriptions/listen stays open for the lifetime of the
// subscription, so a buffering gateway would withhold every notification.
//
// The keep-alive comment line is asserted byte for byte: the spec recommends
// periodic SSE comments to survive idle timeouts, and a gateway that filtered
// or coalesced them would defeat that.
func TestProxyStreamsSSEWithoutBuffering(t *testing.T) {
	const (
		keepAlive = ":\r\n"
		updated   = "event: message\r\ndata: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/resources/updated\"}\r\n\r\n"
	)

	firstChunkRead := make(chan struct{})
	env := newContractEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter does not implement http.Flusher")
			return
		}
		_, _ = io.WriteString(w, keepAlive)
		flusher.Flush()

		// The second chunk is written only after the client has received the
		// first, so reading it proves the stream was not buffered end to end.
		// A failing test never signals, so also unblock on request cancellation
		// to keep the upstream server closable.
		select {
		case <-firstChunkRead:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, updated)
		flusher.Flush()
	}))

	// The upstream holds the stream open until the client has read the first
	// chunk, so a buffering gateway would never return response headers at all.
	// The deadline turns that deadlock into a diagnosable failure.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, env.gateway.URL+"/mcp", strings.NewReader(
		`{"jsonrpc":"2.0","id":2,"method":"subscriptions/listen"}`))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2026-07-28")

	resp, err := env.gateway.Client().Do(req)
	if err != nil {
		t.Fatalf("subscriptions/listen: %v; the gateway did not return stream headers, which means it buffered the response", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if got := resp.Header.Get("Content-Type"); got != "text/event-stream" {
		t.Fatalf("Content-Type: got %q, want %q", got, "text/event-stream")
	}

	reader := bufio.NewReader(resp.Body)
	if got := readLineWithin(t, reader, 3*time.Second); got != keepAlive {
		t.Errorf("keep-alive comment: got %q, want %q", got, keepAlive)
	}
	close(firstChunkRead)

	var got strings.Builder
	for range 3 { // "event:" line, "data:" line, terminating blank line
		got.WriteString(readLineWithin(t, reader, 3*time.Second))
	}
	if got.String() != updated {
		t.Errorf("notification frame: got %q, want %q", got.String(), updated)
	}
}

// readLineWithin reads one line, failing the test if it does not arrive in
// time. A timeout here means the gateway held the chunk back.
func readLineWithin(t *testing.T, reader *bufio.Reader, timeout time.Duration) string {
	t.Helper()

	type readResult struct {
		line string
		err  error
	}
	done := make(chan readResult, 1)
	go func() {
		line, err := reader.ReadString('\n')
		done <- readResult{line: line, err: err}
	}()

	select {
	case result := <-done:
		if result.err != nil {
			t.Fatalf("read SSE line: %v", result.err)
		}
		return result.line
	case <-time.After(timeout):
		t.Fatalf("no SSE line within %s; the gateway buffered the stream", timeout)
		return ""
	}
}

// TestSSEAccelBufferingHint verifies the X-Accel-Buffering contract: the
// upstream value always wins, the gateway supplies the hint only when the
// upstream omitted it on an SSE response, and non-streaming responses are left
// alone.
func TestSSEAccelBufferingHint(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		upstream    string
		want        string
	}{
		{
			name:        "SSE without upstream hint gets one",
			contentType: "text/event-stream",
			want:        "no",
		},
		{
			name:        "SSE with charset parameter is still recognized",
			contentType: "text/event-stream; charset=utf-8",
			want:        "no",
		},
		{
			name:        "upstream hint is preserved",
			contentType: "text/event-stream",
			upstream:    "yes",
			want:        "yes",
		},
		{
			name:        "non-streaming response is untouched",
			contentType: "application/json",
			want:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tt.contentType)
				if tt.upstream != "" {
					w.Header().Set("X-Accel-Buffering", tt.upstream)
				}
				w.WriteHeader(http.StatusOK)
			}))
			defer upstream.Close()

			u, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse upstream URL: %v", err)
			}
			h := NewHandler(u, &mockInvalidator{}, "", "", nil)

			w := httptest.NewRecorder()
			h.ServeHTTP(w, requestWithContext("alice", "tok"))

			if got := w.Header().Get("X-Accel-Buffering"); got != tt.want {
				t.Errorf("X-Accel-Buffering: got %q, want %q", got, tt.want)
			}
		})
	}
}

// TestNegotiationErrorIsNotTreatedAsAuthError verifies that a protocol-level
// rejection from the upstream is passed through as-is. Only an upstream 401 is
// an auth signal; a negotiation failure must not invalidate the client's token
// or acquire a WWW-Authenticate header on the way back.
func TestNegotiationErrorIsNotTreatedAsAuthError(t *testing.T) {
	const negotiationError = `{"jsonrpc":"2.0","id":1,"error":{"code":-32602,"message":"unsupported protocol version"}}`

	env := newContractEnv(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, negotiationError)
	}))

	req, err := http.NewRequest(http.MethodPost, env.gateway.URL+"/mcp", strings.NewReader("{}"))
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	resp := env.do(t, req)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}
	if string(body) != negotiationError {
		t.Errorf("body: got %q, want %q", body, negotiationError)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != "" {
		t.Errorf("WWW-Authenticate on a negotiation error: got %q, want empty", got)
	}
	if len(env.invalidator.tokens) != 0 {
		t.Errorf("token cache invalidated on a negotiation error: %v", env.invalidator.tokens)
	}
}

// TestAuthErrorNeverReachesUpstream verifies the other side of that boundary:
// an auth failure is answered by the gateway with a 401 plus WWW-Authenticate
// and never becomes an upstream request, so it can never be mistaken for a
// protocol negotiation outcome.
func TestAuthErrorNeverReachesUpstream(t *testing.T) {
	var upstreamCalled bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	u, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream URL: %v", err)
	}
	src := &mockProviderTokenSource{err: auth.ErrSubjectNotFound}
	h := NewProviderTokenMiddleware(src, "https://gw.example.com/.well-known/oauth-protected-resource",
		NewHandler(u, &mockInvalidator{}, "", "", nil))

	w := httptest.NewRecorder()
	h.ServeHTTP(w, requestWithContext("alice", "tok"))

	if upstreamCalled {
		t.Error("auth failure was forwarded to the upstream")
	}
	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
	if got := w.Header().Get("WWW-Authenticate"); !strings.Contains(got, "invalid_token") {
		t.Errorf("WWW-Authenticate: got %q, want it to report invalid_token", got)
	}
}
