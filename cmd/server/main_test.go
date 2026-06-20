package main

import (
	"net/url"
	"testing"

	"github.com/scottlz0310/mcp-gateway/internal/router"
)

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
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
				"http://127.0.0.1:8080":                  "mcp-gateway",
				"cloudflare":                             "mcp-gateway",
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
				"http://127.0.0.1:8080":          "mcp-gateway",
				"svc":                            "custom-aud",
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
				"http://127.0.0.1:8080":          "mcp-gateway",
				"svc":                            "mcp-gateway",
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
				"http://127.0.0.1:8080":             "mcp-gateway",
				"secure":                            "mcp-gateway",
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
