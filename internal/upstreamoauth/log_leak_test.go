package upstreamoauth_test

// Regression tests for the PR #194 review finding (issue #193 follow-up):
// when the token endpoint reflects submitted secrets (authorization code,
// refresh token, client secret) into a non-2xx error body, the raw body must
// never reach log output. Only the HTTP status and the normalized OAuth error
// code may be logged. See docs/token-log-audit.md and CONTRIBUTING.md
// "Logging & Secrets".

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

// captureLogs redirects the default slog logger to a buffer and restores it
// via t.Cleanup. Tests using this helper must not call t.Parallel().
func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	old := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(old) })
	return &buf
}

// reflectingTokenServer responds 400 and reflects submitted secrets back in
// the error response, mimicking an AS that echoes request parameters. The
// "error" field itself carries a submitted secret (alphanumeric + hyphens
// only, so a charset/length filter alone would let it through), and
// error_description carries the full form and Authorization header.
func reflectingTokenServer(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		reflected := r.Form.Get("code")
		if reflected == "" {
			reflected = r.Form.Get("refresh_token")
		}
		if reflected == "" {
			reflected = "reflected-marker-MUST-NOT-LOG"
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w,
			`{"error":%q,"error_description":"REFLECTED form=%s authorization=%s"}`,
			reflected, r.Form.Encode(), r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestTokenEndpointErrorLogsDoNotLeakSecrets drives all three token-endpoint
// call paths (authorization_code exchange, refresh_token, client_credentials)
// against a secret-reflecting AS and asserts that the reflected body — even
// via the "error" field itself — never appears in the captured slog output;
// the unknown error value must be classified to the fixed "unknown_error".
func TestTokenEndpointErrorLogsDoNotLeakSecrets(t *testing.T) {
	const (
		routeName    = "myroute"
		publicURL    = "http://localhost:8080"
		clientSecret = "client-secret-MUST-NOT-LOG"
		authCode     = "code-SECRET-MUST-NOT-LOG"
		codeVerifier = "verifier-SECRET-MUST-NOT-LOG"
		refreshToken = "refresh-SECRET-MUST-NOT-LOG"
	)
	clientRecord := func(ts *httptest.Server, grant string) map[string]upstreamoauth.ClientRecord {
		return map[string]upstreamoauth.ClientRecord{
			routeName: {
				RouteName:     routeName,
				Grant:         grant,
				Issuer:        ts.URL,
				TokenEndpoint: ts.URL + "/token",
				ClientID:      "client-id",
				ClientSecret:  clientSecret,
			},
		}
	}

	cases := []struct {
		name        string
		wantLogLine string
		secrets     map[string]string
		run         func(t *testing.T, ts *httptest.Server)
	}{
		{
			name:        "authorization_code exchange",
			wantLogLine: "token exchange failed",
			secrets: map[string]string{
				"authorization code": authCode,
				"code verifier":      codeVerifier,
			},
			run: func(t *testing.T, ts *httptest.Server) {
				stateStore := upstreamoauth.NewStateStore()
				stateStore.Save("state-key", upstreamoauth.OAuthState{
					Subject:      "user@example.com",
					RouteName:    routeName,
					CodeVerifier: codeVerifier,
					ExpiresAt:    time.Now().Add(10 * time.Minute),
				})
				handler := makeCallbackHandler(stateStore, clientRecord(ts, ""),
					auth.NewMemUpstreamTokenStore(), publicURL, ts.Client())

				req := httptest.NewRequest("GET",
					"/upstream/callback/"+routeName+"?state=state-key&code="+authCode, nil)
				req.SetPathValue("routeName", routeName)
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code != http.StatusBadGateway {
					t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
				}
			},
		},
		{
			name:        "refresh_token",
			wantLogLine: "permanent failure",
			secrets: map[string]string{
				"refresh token": refreshToken,
			},
			run: func(t *testing.T, ts *httptest.Server) {
				store := auth.NewMemUpstreamTokenStore()
				_ = store.Save("user", routeName, auth.UpstreamTokenRecord{
					AccessToken:  "old-tok",
					RefreshToken: refreshToken,
					ExpiresAt:    time.Now().Add(time.Minute),
				})
				refresher := makeRefresher(t, clientRecord(ts, ""), store, ts.Client())

				if _, ok := refresher.RefreshAfter401(context.Background(), "user", routeName); ok {
					t.Fatal("expected refresh to fail permanently on 400 invalid_grant")
				}
			},
		},
		{
			name:        "client_credentials",
			wantLogLine: "client_credentials token fetch failed",
			secrets: map[string]string{
				"reflected error marker": "reflected-marker-MUST-NOT-LOG",
			},
			run: func(t *testing.T, ts *httptest.Server) {
				cs := &testClientStore{records: clientRecord(ts, "client_credentials")}
				mgr := upstreamoauth.NewManager(cs, publicURL)
				mw := upstreamoauth.NewAuthorizeMiddleware(
					routeName, ts.URL, "read", "client_credentials", "", mgr,
					upstreamoauth.NewStateStore(), auth.NewMemUpstreamTokenStore(), publicURL,
				)
				handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("next handler must not be called when the token endpoint returns an error")
				}))

				req := httptest.NewRequest("GET", "/mcp/"+routeName+"/sse", nil)
				req = withIdentity(req, "svc@example.com")
				rr := httptest.NewRecorder()
				handler.ServeHTTP(rr, req)

				if rr.Code != http.StatusBadGateway {
					t.Fatalf("status = %d, want %d", rr.Code, http.StatusBadGateway)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			ts := reflectingTokenServer(t)

			tc.run(t, ts)

			out := logs.String()
			if !strings.Contains(out, tc.wantLogLine) {
				t.Fatalf("expected %q log line; got: %s", tc.wantLogLine, out)
			}
			if !strings.Contains(out, "unknown_error") {
				t.Errorf("expected unknown oauth_error to be classified to the fixed value in log; got: %s", out)
			}
			if strings.Contains(out, "REFLECTED") {
				t.Errorf("log output contains reflected token endpoint response body: %s", out)
			}
			tc.secrets["client secret"] = clientSecret
			for name, secret := range tc.secrets {
				if strings.Contains(out, secret) {
					t.Errorf("log output contains raw %s", name)
				}
			}
		})
	}
}
