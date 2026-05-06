package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestParseTrustedProxyCIDRs(t *testing.T) {
	got, err := ParseTrustedProxyCIDRs([]string{"127.0.0.1/32, 10.0.0.0/8", "fc00::/7"})
	if err != nil {
		t.Fatalf("ParseTrustedProxyCIDRs returned error: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("prefix count: got %d, want 3", len(got))
	}
	if !got[0].Contains(netip.MustParseAddr("127.0.0.1")) {
		t.Errorf("first prefix does not contain 127.0.0.1: %v", got[0])
	}
	if !got[1].Contains(netip.MustParseAddr("10.1.2.3")) {
		t.Errorf("second prefix does not contain 10.1.2.3: %v", got[1])
	}
	if !got[2].Contains(netip.MustParseAddr("fc00::1")) {
		t.Errorf("third prefix does not contain fc00::1: %v", got[2])
	}
}

func TestParseTrustedProxyCIDRsRejectsInvalidCIDR(t *testing.T) {
	_, err := ParseTrustedProxyCIDRs([]string{"127.0.0.1"})
	if err == nil {
		t.Fatal("expected invalid CIDR error")
	}
}

func TestProxyHeadersTrustedAppliesForwardedValues(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	var got struct {
		scheme     string
		host       string
		remoteAddr string
	}
	h := ProxyHeaders(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.scheme = r.URL.Scheme
		got.host = r.Host
		got.remoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://internal.local/mcp", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "mcp.example.com")
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 127.0.0.1")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if got.scheme != "https" {
		t.Errorf("scheme: got %q, want https", got.scheme)
	}
	if got.host != "mcp.example.com" {
		t.Errorf("host: got %q, want mcp.example.com", got.host)
	}
	if got.remoteAddr != "203.0.113.9" {
		t.Errorf("remote_addr: got %q, want 203.0.113.9", got.remoteAddr)
	}
}

func TestProxyHeadersUntrustedStripsAndIgnoresForwardedValues(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	var got struct {
		scheme      string
		host        string
		remoteAddr  string
		protoHeader string
		hostHeader  string
		forHeader   string
	}
	h := ProxyHeaders(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.scheme = r.URL.Scheme
		got.host = r.Host
		got.remoteAddr = r.RemoteAddr
		got.protoHeader = r.Header.Get("X-Forwarded-Proto")
		got.hostHeader = r.Header.Get("X-Forwarded-Host")
		got.forHeader = r.Header.Get("X-Forwarded-For")
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://internal.local/mcp", nil)
	r.RemoteAddr = "198.51.100.10:4567"
	r.Header.Set("X-Forwarded-Proto", "https")
	r.Header.Set("X-Forwarded-Host", "mcp.example.com")
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if got.scheme != "http" {
		t.Errorf("scheme should remain original: got %q, want http", got.scheme)
	}
	if got.host != "internal.local" {
		t.Errorf("host should remain original: got %q, want internal.local", got.host)
	}
	if got.remoteAddr != "198.51.100.10:4567" {
		t.Errorf("remote_addr should remain original: got %q", got.remoteAddr)
	}
	if got.protoHeader != "" || got.hostHeader != "" || got.forHeader != "" {
		t.Errorf("forwarded headers should be stripped, got proto=%q host=%q for=%q", got.protoHeader, got.hostHeader, got.forHeader)
	}
}

func TestProxyHeadersInvalidForwardedValuesAreIgnored(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	var got struct {
		scheme     string
		host       string
		remoteAddr string
	}
	h := ProxyHeaders(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.scheme = r.URL.Scheme
		got.host = r.Host
		got.remoteAddr = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://internal.local/mcp", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("X-Forwarded-Proto", "javascript")
	r.Header.Set("X-Forwarded-Host", "bad host")
	r.Header.Set("X-Forwarded-For", "not-an-ip")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if got.scheme != "http" {
		t.Errorf("scheme should remain original: got %q, want http", got.scheme)
	}
	if got.host != "internal.local" {
		t.Errorf("host should remain original: got %q, want internal.local", got.host)
	}
	if got.remoteAddr != "127.0.0.1:4567" {
		t.Errorf("remote_addr should remain original: got %q", got.remoteAddr)
	}
}

func TestProxyHeadersSupportsTrustedIPv6Proxy(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("::1/128")}
	var got string
	h := ProxyHeaders(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
		w.WriteHeader(http.StatusNoContent)
	}))

	r := httptest.NewRequest(http.MethodGet, "http://internal.local/mcp", nil)
	r.RemoteAddr = "[::1]:4567"
	r.Header.Set("X-Forwarded-For", "2001:db8::10")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	if got != "2001:db8::10" {
		t.Errorf("remote_addr: got %q, want 2001:db8::10", got)
	}
}

func TestProxyHeadersBeforeLoggerLogsForwardedClientIP(t *testing.T) {
	var buf bytes.Buffer
	t.Cleanup(captureLogs(t, &buf))

	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	h := ProxyHeaders(trusted)(Logger()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})))

	r := httptest.NewRequest(http.MethodGet, "http://internal.local/mcp", nil)
	r.RemoteAddr = "127.0.0.1:4567"
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	w := httptest.NewRecorder()

	h.ServeHTTP(w, r)

	entry := parseLastLog(t, &buf)
	if entry["remote_addr"] != "203.0.113.9" {
		t.Errorf("remote_addr log field: got %v, want 203.0.113.9", entry["remote_addr"])
	}
}
