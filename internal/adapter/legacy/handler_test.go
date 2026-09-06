package legacy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/middleware"
	"github.com/scottlz0310/mcp-gateway/internal/proxy"
)

const discoverResult = `{"jsonrpc":"2.0","id":9007199254740993,"result":{"resultType":"complete","supportedVersions":["2026-07-28"],"_meta":{"io.modelcontextprotocol/serverInfo":{"name":"upstream","version":"1.0"}},"capabilities":{"tools":{"listChanged":true},"resources":{"subscribe":true,"listChanged":true},"prompts":{},"logging":{},"experimental":{"private":{}}},"instructions":"案内"}}`

func request(body, version string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "http://gateway/mcp", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if version != "" {
		r.Header.Set("Mcp-Protocol-Version", version)
	}
	return r
}

func decode(t *testing.T, reader io.Reader) object {
	t.Helper()
	var msg object
	if err := json.NewDecoder(reader).Decode(&msg); err != nil {
		t.Fatal(err)
	}
	return msg
}

func TestInitialize(t *testing.T) {
	for _, version := range []string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"} {
		for _, sse := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/SSE=%t", version, sse), func(t *testing.T) {
				next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					msg := decode(t, r.Body)
					params, _ := readObject(msg["params"])
					meta, _ := readObject(params["_meta"])
					if stringValue(msg["method"]) != "server/discover" || string(msg["id"]) != "9007199254740993" ||
						stringValue(meta[versionKey]) != modernVersion || string(meta[capabilitiesKey]) != "{}" ||
						r.Header.Get("Mcp-Method") != "server/discover" || r.Header.Get("Mcp-Protocol-Version") != modernVersion || r.Header.Get("Mcp-Session-Id") != "" {
						t.Fatalf("discovery 変換が不正: %s / %v", msg, r.Header)
					}
					w.Header().Set("Etag", "old")
					w.Header().Set("Mcp-Session-Id", "unexpected")
					if sse {
						w.Header().Set("Content-Type", "text/event-stream")
						_, _ = fmt.Fprintf(w, ": keepalive\r\n\r\ndata: %s\r\n\r\n", discoverResult)
					} else {
						_, _ = io.WriteString(w, discoverResult)
					}
				})
				r := request(`{"jsonrpc":"2.0","id":9007199254740993,"method":"initialize","params":{"protocolVersion":"`+version+`","capabilities":{"sampling":{}},"clientInfo":{"name":"agy","version":"1"}}}`, "")
				r.Header.Set("Mcp-Session-Id", "old")
				w := httptest.NewRecorder()
				NewHandler(next).ServeHTTP(w, r)
				if w.Code != 200 {
					t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
				}
				msg := decode(t, w.Body)
				result, _ := readObject(msg["result"])
				caps, _ := readObject(result["capabilities"])
				if stringValue(result["protocolVersion"]) != version || string(msg["id"]) != "9007199254740993" ||
					string(caps["resources"]) != "{}" || string(caps["tools"]) != "{}" || len(caps["logging"]) != 0 ||
					stringValue(result["instructions"]) != "案内" || w.Header().Get("Etag") != "" || w.Header().Get("Mcp-Session-Id") != "" {
					t.Fatalf("initialize 応答が不正: %s / %v", result, w.Header())
				}
			})
		}
	}
}

func TestRPCThroughProxy(t *testing.T) {
	for _, tc := range []struct{ method, params, name string }{
		{"tools/list", `{}`, ""},
		{"tools/call", `{"name":"lookup","arguments":{"number":9007199254740993},"_meta":{"progressToken":"p"}}`, "lookup"},
		{"resources/read", `{"uri":"file:///日本語"}`, "=?base64?ZmlsZTovLy/ml6XmnKzoqp4=?="},
		{"prompts/get", `{"name":"example"}`, "example"},
	} {
		t.Run(tc.method, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				msg := decode(t, r.Body)
				params, _ := readObject(msg["params"])
				meta, _ := readObject(params["_meta"])
				if r.URL.Path != "/rpc" || r.Header.Get("Authorization") != "Bearer upstream-secret" || r.Header.Get("X-Authenticated-User") != "alice" ||
					r.Header.Get("Mcp-Method") != tc.method || r.Header.Get("Mcp-Name") != tc.name || r.Header.Get("Mcp-Protocol-Version") != modernVersion ||
					r.Header.Get("Accept") != "application/json, text/event-stream" || stringValue(meta[versionKey]) != modernVersion || string(meta[capabilitiesKey]) != "{}" {
					t.Error("認証・ルート・protocol の中継が不正")
				}
				if tc.method == "tools/call" && (stringValue(meta["progressToken"]) != "p" || !strings.Contains(string(params["arguments"]), "9007199254740993")) {
					t.Error("RPC データが失われました")
				}
				w.WriteHeader(http.StatusTeapot)
				_, _ = io.WriteString(w, `{"jsonrpc":"2.0","id":"req","error":{"code":-32001,"message":"example"}}`)
			}))
			defer upstream.Close()
			u, _ := url.Parse(upstream.URL + "/rpc")
			t.Setenv("TEST_LEGACY_UPSTREAM_TOKEN", "upstream-secret")
			h := NewHandler(proxy.NewHandler(u, nil, "TEST_LEGACY_UPSTREAM_TOKEN", "/mcp", nil))
			r := request(`{"jsonrpc":"2.0","id":"req","method":"`+tc.method+`","params":`+tc.params+`}`, "2025-06-18")
			r.Header.Set("Accept", "application/json")
			r.Header.Set("Authorization", "Bearer client-secret")
			r.Header.Set("X-Authenticated-User", "mallory")
			r = r.WithContext(context.WithValue(r.Context(), middleware.ContextKeyIdentity, "alice"))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusTeapot || !strings.Contains(w.Body.String(), `"code":-32001`) {
				t.Fatalf("エラーが透過されません: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBypass(t *testing.T) {
	for _, tc := range []struct{ name, body, version string }{
		{"modern", ` {"jsonrpc":"2.0","id":1,"method":"tools/call"} `, modernVersion},
		{"discover", ` {"jsonrpc":"2.0","id":1,"method":"server/discover"} `, ""},
		{"metadata", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}}`, ""},
		{"future", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, "2099-01-01"},
		{"invalid", `{invalid`, ""},
		{"null params", `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":null}`, ""},
		{"batch", `[{"jsonrpc":"2.0","id":1,"method":"tools/list"}]`, ""},
		{"unknown initialize", `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2099-01-01"}}`, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := request(tc.body, tc.version)
			NewHandler(http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
				body, _ := io.ReadAll(got.Body)
				if string(body) != tc.body || got.Header.Get("Mcp-Protocol-Version") != tc.version {
					t.Error("透過リクエストが変更されました")
				}
				w.WriteHeader(400)
				_, _ = io.WriteString(w, "unchanged")
			})).ServeHTTP(httptest.NewRecorder(), r)
		})
	}
}

type unreadable struct{ t *testing.T }

func (b unreadable) Read([]byte) (int, error) {
	b.t.Error("modern 本文を事前に読み取りました")
	return 0, io.EOF
}
func (b unreadable) Close() error { return nil }

func TestModernFastPath(t *testing.T) {
	r := request("", modernVersion)
	r.Body = unreadable{t}
	called := false
	NewHandler(http.HandlerFunc(func(w http.ResponseWriter, got *http.Request) {
		called = true
		if got != r {
			t.Error("リクエストを複製しました")
		}
	})).ServeHTTP(httptest.NewRecorder(), r)
	if !called {
		t.Fatal("プロキシ未呼び出し")
	}
}

func TestInitialized(t *testing.T) {
	w := httptest.NewRecorder()
	NewHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Fatal("通知が upstream に到達しました") })).ServeHTTP(w, request(`{"jsonrpc":"2.0","method":"notifications/initialized"}`, ""))
	if w.Code != 202 || w.Body.Len() != 0 {
		t.Fatalf("status=%d", w.Code)
	}
}

func TestLegacyNotificationsAreAbsorbed(t *testing.T) {
	for _, method := range []string{"notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"} {
		t.Run(method, func(t *testing.T) {
			called := false
			w := httptest.NewRecorder()
			NewHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(w,
				request(`{"jsonrpc":"2.0","method":"`+method+`","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2025-06-18"}}}`, "2025-06-18"))
			if called || w.Code != http.StatusAccepted || w.Body.Len() != 0 {
				t.Fatalf("通知が吸収されません: called=%t status=%d body=%q", called, w.Code, w.Body.String())
			}
		})
	}
}

func TestDiscoveryFailure(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
		want   int
	}{
		{"auth", 401, "denied", 401},
		{"protocol", 400, `{"error":{"code":-32022}}`, 400},
		{"RPC error", 200, `{"jsonrpc":"2.0","id":1,"error":{"code":-32603}}`, 200},
		{"invalid JSON", 200, "broken", 502},
		{"wrong ID", 200, discoverResult, 502},
		{"unsupported", 200, `{"jsonrpc":"2.0","id":1,"result":{"supportedVersions":["2025-06-18"]}}`, 502},
		{"too large", 200, strings.Repeat("x", maxBody+1), 502},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("WWW-Authenticate", "Bearer")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})).ServeHTTP(w, request(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`, ""))
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
			if tc.want != 502 && (w.Body.String() != tc.body || w.Header().Get("WWW-Authenticate") != "Bearer") {
				t.Error("エラー応答が変更されました")
			}
		})
	}
}

func TestDiscoveryFailureLogsReasonWithoutBody(t *testing.T) {
	var logs bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&logs, nil)))
	defer slog.SetDefault(previous)

	w := httptest.NewRecorder()
	NewHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "secret upstream body")
	})).ServeHTTP(w, request(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`, ""))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status=%d", w.Code)
	}
	if got := logs.String(); !strings.Contains(got, "legacy adapter discovery failed") || !strings.Contains(got, "reason=invalid_response") || !strings.Contains(got, "upstream_status=200") || strings.Contains(got, "secret upstream body") {
		t.Fatalf("diagnostic log が不正です: %s", got)
	}
}

func TestModernStream(t *testing.T) {
	continueStream := make(chan struct{})
	server := httptest.NewServer(NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("X-Accel-Buffering", "no")
		_, _ = io.WriteString(w, ": keepalive\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-continueStream:
		case <-r.Context().Done():
		}
	})))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r, _ := http.NewRequestWithContext(ctx, http.MethodPost, server.URL, strings.NewReader(`{"method":"subscriptions/listen"}`))
	r.Header.Set("Mcp-Protocol-Version", modernVersion)
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	first := make([]byte, len(": keepalive\n\n"))
	if _, err := io.ReadFull(resp.Body, first); err != nil {
		t.Fatal(err)
	}
	close(continueStream)
	if string(first) != ": keepalive\n\n" || resp.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatal("SSE の透過性が失われました")
	}
}

type rejectedToken struct{}

func (rejectedToken) ValidateToken(context.Context, string, string) (string, string, error) {
	return "", "", fmt.Errorf("認証拒否")
}

func TestAuthenticationBeforeAdapter(t *testing.T) {
	for _, method := range []string{"initialize", "notifications/initialized"} {
		t.Run(method, func(t *testing.T) {
			h := middleware.Auth(rejectedToken{})(NewHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				t.Fatal("未認証のリクエストが upstream に到達しました")
			})))
			r := request(`{"jsonrpc":"2.0","method":"`+method+`","params":{"protocolVersion":"2024-11-05"}}`, "")
			r.Header.Set("Authorization", "Bearer invalid")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 401 || w.Header().Get("WWW-Authenticate") == "" {
				t.Fatalf("アダプタが認証を迂回しました: %d", w.Code)
			}
		})
	}
}

type refreshedToken struct{ calls int }

func (*refreshedToken) Token(context.Context) (string, error) { return "stale", nil }
func (s *refreshedToken) RefreshAfter401(context.Context, string) (string, error) {
	s.calls++
	return "fresh", nil
}

func TestDiscoveryCredentialRefresh(t *testing.T) {
	source := &refreshedToken{}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		msg := decode(t, r.Body)
		if stringValue(msg["method"]) != "server/discover" {
			t.Error("再送する本文が不正")
		}
		if r.Header.Get("Authorization") != "Bearer fresh" {
			w.WriteHeader(401)
			return
		}
		_, _ = io.WriteString(w, discoverResult)
	}))
	defer upstream.Close()
	u, _ := url.Parse(upstream.URL)
	h := NewHandler(proxy.NewHandler(u, nil, "", "/mcp", nil, proxy.WithServerTokenSource("test", source)))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(`{"jsonrpc":"2.0","id":9007199254740993,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`, ""))
	if w.Code != 200 || source.calls != 1 {
		t.Fatalf("status=%d refresh=%d body=%s", w.Code, source.calls, w.Body.String())
	}
}

func TestModernProxyContract(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		for _, tc := range []struct {
			method, body string
			status       int
		}{
			{http.MethodPost, ` {"jsonrpc":"2.0","id":"modern","method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28"}}} `, 200},
			{http.MethodPost, `{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"wrong"}}}`, 400},
			{http.MethodGet, "", 405},
			{http.MethodDelete, "", 405},
		} {
			t.Run(fmt.Sprintf("adapter=%t/%s/%d", enabled, tc.method, tc.status), func(t *testing.T) {
				upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body, _ := io.ReadAll(r.Body)
					if string(body) != tc.body || r.Method != tc.method || r.Header.Get("Mcp-Protocol-Version") != modernVersion || r.Header.Get("Mcp-Session-Id") != "client-session" {
						t.Error("modern リクエストの透過契約違反")
					}
					w.Header().Set("Mcp-Protocol-Version", modernVersion)
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, "upstream response")
				}))
				defer upstream.Close()
				u, _ := url.Parse(upstream.URL)
				h := proxy.NewHandler(u, nil, "", "/mcp", nil)
				if enabled {
					h = NewHandler(h)
				}
				r := request(tc.body, modernVersion)
				r.Method = tc.method
				r.Header.Set("Mcp-Session-Id", "client-session")
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != tc.status || w.Body.String() != "upstream response" || w.Header().Get("Mcp-Protocol-Version") != modernVersion || w.Header().Get("Mcp-Session-Id") != "" {
					t.Error("modern 応答の透過契約違反")
				}
			})
		}
	}
}
