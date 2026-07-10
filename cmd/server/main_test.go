package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/router"
)

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

// writeSelfSignedCert generates a self-signed certificate for 127.0.0.1 and
// writes the PEM cert/key pair into dir, returning their paths.
func writeSelfSignedCert(t *testing.T, dir string) (certPath, keyPath string) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcp-gateway test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}

func TestValidateTLSConfig(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	tests := []struct {
		name    string
		cert    string
		key     string
		wantErr bool
	}{
		{name: "both empty: TLS disabled", cert: "", key: "", wantErr: false},
		{name: "both set and files exist", cert: certPath, key: keyPath, wantErr: false},
		{name: "cert only", cert: certPath, key: "", wantErr: true},
		{name: "key only", cert: "", key: keyPath, wantErr: true},
		{name: "cert file missing", cert: filepath.Join(dir, "missing-cert.pem"), key: keyPath, wantErr: true},
		{name: "key file missing", cert: certPath, key: filepath.Join(dir, "missing-key.pem"), wantErr: true},
		{name: "cert path is a directory", cert: dir, key: keyPath, wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := validateTLSConfig(tc.cert, tc.key)
			if (err != nil) != tc.wantErr {
				t.Errorf("validateTLSConfig(%q, %q) = %v, wantErr %v", tc.cert, tc.key, err, tc.wantErr)
			}
		})
	}
}

func TestListenAndServeTLS(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	certPath, keyPath := writeSelfSignedCert(t, dir)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}

	srv := &http.Server{
		Addr: addr,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	errCh := make(chan error, 1)
	go func() { errCh <- listenAndServe(srv, certPath, keyPath) }()
	t.Cleanup(func() { _ = srv.Close() })

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(certPEM) {
		t.Fatal("failed to add test certificate to pool")
	}
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}},
		Timeout:   5 * time.Second,
	}

	var resp *http.Response
	deadline := time.Now().Add(5 * time.Second)
	for {
		resp, err = client.Get("https://" + addr + "/")
		if err == nil || time.Now().After(deadline) {
			break
		}
		select {
		case srvErr := <-errCh:
			t.Fatalf("server exited before accepting connections: %v", srvErr)
		case <-time.After(50 * time.Millisecond):
		}
	}
	if err != nil {
		t.Fatalf("HTTPS request failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("status: got %d, want %d", resp.StatusCode, http.StatusNoContent)
	}

	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-errCh; !errors.Is(err, http.ErrServerClosed) {
		t.Errorf("listenAndServe returned %v, want http.ErrServerClosed", err)
	}
}

func TestBuildResourceAudienceMap(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		publicURL string
		routes    []router.Route
		want      map[string]string
	}{
		{
			name:      "no routes: only gateway-wide baseline registered",
			publicURL: "http://127.0.0.1:8080",
			routes:    nil,
			want: map[string]string{
				"http://127.0.0.1:8080": "mcp-gateway",
			},
		},
		{
			name:      "non-root prefix: name form and URL form both registered",
			publicURL: "http://127.0.0.1:8080",
			routes: []router.Route{
				{Name: "cloudflare", Prefix: "/mcp/cloudflare", Upstream: mustURL("https://mcp.cloudflare.com/mcp"), RequiredAudience: "mcp-gateway"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080":                "mcp-gateway",
				"cloudflare":                           "mcp-gateway",
				"http://127.0.0.1:8080/mcp/cloudflare": "mcp-gateway",
			},
		},
		{
			name:      "URL form resolves RFC 8707 resource from per-route PRM",
			publicURL: "http://127.0.0.1:8080",
			routes: []router.Route{
				{Name: "svc", Prefix: "/mcp/svc", Upstream: mustURL("http://svc:9000"), RequiredAudience: "custom-aud"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080":         "mcp-gateway",
				"svc":                           "custom-aud",
				"http://127.0.0.1:8080/mcp/svc": "custom-aud",
			},
		},
		{
			name:      "root prefix overrides gateway-wide baseline with route audience",
			publicURL: "http://127.0.0.1:8080",
			routes: []router.Route{
				{Name: "default", Prefix: "/", Upstream: mustURL("http://upstream:8000"), RequiredAudience: "custom-aud"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080": "custom-aud",
				"default":               "custom-aud",
			},
		},
		{
			name:      "NoAuth routes are excluded from the map",
			publicURL: "http://127.0.0.1:8080",
			routes: []router.Route{
				{Name: "public", Prefix: "/public", Upstream: mustURL("http://public:8000"), NoAuth: true, RequiredAudience: "mcp-gateway"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080": "mcp-gateway",
			},
		},
		{
			name:      "publicURL trailing slash is normalised",
			publicURL: "http://127.0.0.1:8080/",
			routes: []router.Route{
				{Name: "svc", Prefix: "/mcp/svc", Upstream: mustURL("http://svc:8000"), RequiredAudience: "mcp-gateway"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080":         "mcp-gateway",
				"svc":                           "mcp-gateway",
				"http://127.0.0.1:8080/mcp/svc": "mcp-gateway",
			},
		},
		{
			name:      "mixed auth and no-auth routes: only auth routes registered",
			publicURL: "http://127.0.0.1:8080",
			routes: []router.Route{
				{Name: "secure", Prefix: "/mcp/secure", Upstream: mustURL("http://secure:8000"), RequiredAudience: "mcp-gateway"},
				{Name: "open", Prefix: "/mcp/open", Upstream: mustURL("http://open:8000"), NoAuth: true, RequiredAudience: "mcp-gateway"},
			},
			want: map[string]string{
				"http://127.0.0.1:8080":            "mcp-gateway",
				"secure":                           "mcp-gateway",
				"http://127.0.0.1:8080/mcp/secure": "mcp-gateway",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := buildResourceAudienceMap(tc.routes, tc.publicURL)
			if len(got) != len(tc.want) {
				t.Errorf("map size: got %d, want %d\ngot:  %v\nwant: %v", len(got), len(tc.want), got, tc.want)
				return
			}
			for k, wantV := range tc.want {
				gotV, ok := got[k]
				if !ok {
					t.Errorf("missing key %q; full map: %v", k, got)
					continue
				}
				if gotV != wantV {
					t.Errorf("key %q: got %q, want %q", k, gotV, wantV)
				}
			}
			for k := range got {
				if _, ok := tc.want[k]; !ok {
					t.Errorf("unexpected key %q in result", k)
				}
			}
		})
	}
}
