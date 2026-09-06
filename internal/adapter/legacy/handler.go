package legacy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

const (
	modernVersion   = "2026-07-28"
	versionKey      = "io.modelcontextprotocol/protocolVersion"
	capabilitiesKey = "io.modelcontextprotocol/clientCapabilities"
	maxBody         = 8 << 20
)

type object = map[string]json.RawMessage

// NewHandler は認証済みのリクエストを既存プロキシ経由で変換する。接続状態は保持しない。
func NewHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		version := r.Header.Get("Mcp-Protocol-Version")
		if r.Method != http.MethodPost || r.Body == nil || version == modernVersion ||
			(version != "" && !legacyVersion(version)) || r.Header.Get("Mcp-Method") == "server/discover" {
			next.ServeHTTP(w, r)
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
		if err != nil {
			http.Error(w, "legacy リクエスト本文を読み取れません", http.StatusBadRequest)
			return
		}
		// 判定対象外の本文は読み取った部分を戻し、そのままプロキシへ渡す。
		r.Body = &replayBody{Reader: io.MultiReader(bytes.NewReader(body), r.Body), Closer: r.Body}
		var msg object
		if len(body) > maxBody || json.Unmarshal(body, &msg) != nil || msg == nil || string(msg["jsonrpc"]) != `"2.0"` {
			next.ServeHTTP(w, r)
			return
		}
		method := stringValue(msg["method"])
		params, ok := readObject(msg["params"])
		if !ok || method == "" || method == "server/discover" {
			next.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(method, "notifications/") && isNotification(msg["id"]) {
			w.WriteHeader(http.StatusAccepted)
			return
		}
		meta, ok := readObject(params["_meta"])
		if !ok || len(meta[versionKey]) > 0 {
			next.ServeHTTP(w, r)
			return
		}
		if len(msg["id"]) == 0 || string(msg["id"]) == "null" {
			next.ServeHTTP(w, r)
			return
		}
		requestedVersion := ""
		if method == "initialize" {
			requestedVersion = stringValue(params["protocolVersion"])
			if !legacyVersion(requestedVersion) {
				next.ServeHTTP(w, r)
				return
			}
			method = "server/discover"
			params = object{}
			meta = object{}
			msg["method"] = json.RawMessage(`"server/discover"`)
		}
		// セッションを持たないため callback capability を引き継がない。
		meta[versionKey] = json.RawMessage(`"` + modernVersion + `"`)
		meta[capabilitiesKey] = json.RawMessage(`{}`)
		params["_meta"], _ = json.Marshal(meta)
		msg["params"], _ = json.Marshal(params)
		converted, err := json.Marshal(msg)
		if err != nil {
			http.Error(w, "legacy リクエストの変換に失敗しました", http.StatusBadRequest)
			return
		}
		out := r.Clone(r.Context())
		out.Body = io.NopCloser(bytes.NewReader(converted))
		out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(converted)), nil }
		out.ContentLength = int64(len(converted))
		out.TransferEncoding = nil
		out.Header.Del("Content-Length")
		out.Header.Del("Mcp-Session-Id")
		out.Header.Set("Mcp-Protocol-Version", modernVersion)
		out.Header.Set("Mcp-Method", method)
		ensureAcceptHeader(out.Header)
		out.Header.Del("Mcp-Name")
		name := ""
		switch method {
		case "tools/call", "prompts/get":
			name = stringValue(params["name"])
		case "resources/read":
			name = stringValue(params["uri"])
		}
		if name != "" {
			out.Header.Set("Mcp-Name", headerValue(name))
		}
		if requestedVersion == "" {
			next.ServeHTTP(w, out)
			return
		}
		initialize(w, out, next, msg["id"], requestedVersion)
	})
}

type replayBody struct {
	io.Reader
	io.Closer
}

func legacyVersion(version string) bool {
	return slices.Contains([]string{"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}, version)
}

func isNotification(id json.RawMessage) bool {
	return len(id) == 0 || string(id) == "null"
}

func stringValue(raw json.RawMessage) string {
	var value string
	_ = json.Unmarshal(raw, &value)
	return value
}

func readObject(raw json.RawMessage) (object, bool) {
	value := object{}
	if len(raw) == 0 {
		return value, true
	}
	err := json.Unmarshal(raw, &value)
	return value, err == nil && value != nil
}

func headerValue(value string) string {
	if strings.HasPrefix(value, "=?base64?") || strings.TrimSpace(value) != value ||
		strings.ContainsFunc(value, func(r rune) bool { return r < 0x20 || r > 0x7e }) {
		return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(value)) + "?="
	}
	return value
}

func ensureAcceptHeader(header http.Header) {
	value := strings.Join(header.Values("Accept"), ",")
	parts := make([]string, 0, 3)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			parts = append(parts, part)
		}
	}
	if !hasMediaType(parts, "application/json") {
		parts = append(parts, "application/json")
	}
	if !hasMediaType(parts, "text/event-stream") {
		parts = append(parts, "text/event-stream")
	}
	header.Set("Accept", strings.Join(parts, ", "))
}

func hasMediaType(parts []string, want string) bool {
	for _, part := range parts {
		mediaType := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		if strings.EqualFold(mediaType, want) {
			return true
		}
	}
	return false
}

// discovery のみ期限とサイズを制限して捕捉する。通常 RPC/SSE はバッファリングしない。
func initialize(w http.ResponseWriter, r *http.Request, next http.Handler, id json.RawMessage, version string) {
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	r.Header.Set("Accept", "application/json, text/event-stream")
	r.Header.Set("Accept-Encoding", "identity")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Del("If-None-Match")
	r.Header.Del("If-Modified-Since")
	response := &capture{header: http.Header{}, cancel: cancel}
	response.serve(next, r)
	if response.failed || ctx.Err() != nil {
		reason := response.failureReason
		if reason == "" {
			reason = "context_canceled"
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				reason = "timeout"
			}
		}
		discoveryFailure(w, reason, response.status)
		return
	}
	if response.status != http.StatusOK {
		slog.Warn("legacy adapter discovery failed", "reason", "upstream_http_error", "upstream_status", response.status)
		copyResponse(w, response.header, response.status, response.body.Bytes())
		return
	}
	payload := response.body.Bytes()
	if strings.HasPrefix(response.header.Get("Content-Type"), "text/event-stream") {
		payload = sseResult(payload, id)
	}
	var msg object
	if json.Unmarshal(payload, &msg) != nil || stringValue(msg["jsonrpc"]) != "2.0" || !bytes.Equal(bytes.TrimSpace(msg["id"]), bytes.TrimSpace(id)) {
		discoveryFailure(w, "invalid_response", response.status)
		return
	}
	if len(msg["error"]) > 0 {
		slog.Warn("legacy adapter discovery failed", "reason", "upstream_jsonrpc_error", "upstream_status", response.status)
		copyResponse(w, response.header, response.status, response.body.Bytes())
		return
	}
	result, ok := readObject(msg["result"])
	var versions []string
	if !ok || json.Unmarshal(result["supportedVersions"], &versions) != nil || !slices.Contains(versions, modernVersion) {
		discoveryFailure(w, "unsupported_protocol_version", response.status)
		return
	}
	meta, _ := readObject(result["_meta"])
	serverInfo := meta["io.modelcontextprotocol/serverInfo"]
	info, ok := readObject(serverInfo)
	if !ok || stringValue(info["name"]) == "" || stringValue(info["version"]) == "" {
		discoveryFailure(w, "missing_server_info", response.status)
		return
	}
	caps, ok := readObject(result["capabilities"])
	if !ok || len(result["capabilities"]) == 0 {
		discoveryFailure(w, "invalid_capabilities", response.status)
		return
	}
	legacyCaps := object{}
	for _, key := range []string{"tools", "resources", "prompts", "completions"} {
		if _, exists := caps[key]; exists {
			legacyCaps[key] = json.RawMessage(`{}`)
		}
	}
	encodedCaps, _ := json.Marshal(legacyCaps)
	legacyResult := object{"protocolVersion": json.RawMessage(`"` + version + `"`), "serverInfo": serverInfo, "capabilities": encodedCaps}
	if instructions, exists := result["instructions"]; exists {
		legacyResult["instructions"] = instructions
	}
	msg["result"], _ = json.Marshal(legacyResult)
	converted, err := json.Marshal(msg)
	if err != nil {
		discoveryFailure(w, "response_encoding", response.status)
		return
	}
	for _, key := range []string{"Content-Length", "Content-Encoding", "Etag", "Mcp-Session-Id", "Mcp-Protocol-Version"} {
		response.header.Del(key)
	}
	response.header.Set("Content-Type", "application/json")
	response.header.Set("Cache-Control", "no-store")
	copyResponse(w, response.header, http.StatusOK, converted)
}

type capture struct {
	header        http.Header
	status        int
	body          bytes.Buffer
	cancel        context.CancelFunc
	failed        bool
	failureReason string
}

func (c *capture) Header() http.Header { return c.header }
func (c *capture) WriteHeader(status int) {
	if c.status == 0 && status >= 200 {
		c.status = status
	}
}
func (c *capture) Write(body []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.body.Len()+len(body) > maxBody {
		c.failed = true
		c.failureReason = "response_too_large"
		c.cancel()
		return 0, errors.New("discovery 応答がサイズ上限を超えました")
	}
	return c.body.Write(body)
}
func (c *capture) Flush() {}
func (c *capture) serve(next http.Handler, r *http.Request) {
	defer func() {
		if p := recover(); p != nil {
			if p != http.ErrAbortHandler {
				panic(p)
			}
			c.failed = true
			c.failureReason = "upstream_handler_failed"
		}
	}()
	next.ServeHTTP(c, r)
	if c.status == 0 {
		c.status = http.StatusOK
	}
}

func discoveryFailure(w http.ResponseWriter, reason string, upstreamStatus int) {
	slog.Warn("legacy adapter discovery failed", "reason", reason, "upstream_status", upstreamStatus)
	http.Error(w, "upstream discovery の変換に失敗しました", http.StatusBadGateway)
}

func copyResponse(w http.ResponseWriter, header http.Header, status int, body []byte) {
	for key, values := range header {
		w.Header()[key] = values
	}
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func sseResult(body []byte, id json.RawMessage) []byte {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 4096), maxBody)
	var data []byte
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			var msg object
			if json.Unmarshal(data, &msg) == nil && bytes.Equal(bytes.TrimSpace(msg["id"]), bytes.TrimSpace(id)) {
				return data
			}
			data = nil
		} else if value, found := strings.CutPrefix(line, "data:"); found {
			data = append(data, strings.TrimPrefix(value, " ")...)
			data = append(data, '\n')
		}
	}
	return nil
}
