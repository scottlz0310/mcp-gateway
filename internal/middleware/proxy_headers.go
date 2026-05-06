package middleware

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"unicode"
)

var forwardedHeaderNames = []string{
	"Forwarded",
	"X-Forwarded-For",
	"X-Forwarded-Host",
	"X-Forwarded-Proto",
	"X-Real-Ip",
}

// ParseTrustedProxyCIDRs validates trusted proxy CIDR strings. Empty items are
// ignored so callers can pass comma-separated env values directly after Split.
func ParseTrustedProxyCIDRs(values []string) ([]netip.Prefix, error) {
	var prefixes []netip.Prefix
	for _, value := range values {
		for _, raw := range strings.Split(value, ",") {
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(raw)
			if err != nil {
				return nil, fmt.Errorf("trusted proxy CIDR %q: %w", raw, err)
			}
			prefixes = append(prefixes, prefix.Masked())
		}
	}
	return prefixes, nil
}

// ProxyHeaders applies X-Forwarded-* headers only when the immediate peer is in
// a configured trusted proxy CIDR. Untrusted forwarded headers are stripped so
// downstream handlers cannot accidentally treat client-supplied values as real.
func ProxyHeaders(trustedProxies []netip.Prefix) func(http.Handler) http.Handler {
	trustedProxies = append([]netip.Prefix(nil), trustedProxies...)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			remoteIP, ok := remoteAddrIP(r.RemoteAddr)
			if !ok || !isTrustedProxy(remoteIP, trustedProxies) {
				next.ServeHTTP(w, withoutForwardedHeaders(r))
				return
			}

			r2 := r.Clone(r.Context())
			if proto := strings.ToLower(firstHeaderValue(r.Header.Get("X-Forwarded-Proto"))); proto == "http" || proto == "https" {
				r2.URL.Scheme = proto
			}
			if host := firstHeaderValue(r.Header.Get("X-Forwarded-Host")); validForwardedHost(host) {
				r2.Host = host
			}
			if clientIP, ok := forwardedClientIP(r.Header.Get("X-Forwarded-For")); ok {
				r2.RemoteAddr = clientIP.String()
			}

			next.ServeHTTP(w, r2)
		})
	}
}

func withoutForwardedHeaders(r *http.Request) *http.Request {
	r2 := r.Clone(r.Context())
	for _, name := range forwardedHeaderNames {
		r2.Header.Del(name)
	}
	return r2
}

func isTrustedProxy(remote netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(remote) {
			return true
		}
	}
	return false
}

func remoteAddrIP(remoteAddr string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		addr, parseErr := netip.ParseAddr(host)
		return addr, parseErr == nil
	}
	addr, parseErr := netip.ParseAddr(remoteAddr)
	return addr, parseErr == nil
}

func forwardedClientIP(header string) (netip.Addr, bool) {
	raw := firstHeaderValue(header)
	if raw == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(raw)
	return addr, err == nil
}

func firstHeaderValue(header string) string {
	beforeComma, _, _ := strings.Cut(header, ",")
	return strings.TrimSpace(beforeComma)
}

func validForwardedHost(host string) bool {
	if host == "" {
		return false
	}
	for _, r := range host {
		if unicode.IsControl(r) || unicode.IsSpace(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}
