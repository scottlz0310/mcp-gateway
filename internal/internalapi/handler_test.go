package internalapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth"
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
)

const testSecret = "test-secret-32-characters-long-aaa"

// fakeResolver lets tests script the behavior of EnsureFreshAccessTokenForSubject
// without spinning up the real auth.Handler (which requires an OAuth provider,
// key material, route configuration, etc).
type fakeResolver struct {
	result auth.DelegatedAccessResult
	err    error

	gotSubject string
	calls      int
}

type fakeFailureReader struct {
	failures []authaudit.Event
}

func (f *fakeFailureReader) RecentAuthFailures() []authaudit.Event {
	return append([]authaudit.Event(nil), f.failures...)
}

func (f *fakeResolver) EnsureFreshAccessTokenForSubject(_ context.Context, subject string) (auth.DelegatedAccessResult, error) {
	f.calls++
	f.gotSubject = subject
	if f.err != nil {
		return auth.DelegatedAccessResult{}, f.err
	}
	return f.result, nil
}

// newTestServer wires up a Handler on an httptest server. The test server
// automatically uses 127.0.0.1, so the loopback check is exercised end-to-end.
func newTestServer(t *testing.T, resolver TokenResolver, secret string) (*httptest.Server, func()) {
	t.Helper()
	h, err := NewHandler(resolver, secret)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	return srv, srv.Close
}

func TestNewHandlerRejectsShortSecret(t *testing.T) {
	_, err := NewHandler(&fakeResolver{}, "short")
	if err == nil {
		t.Fatal("expected error for short secret")
	}
}

func TestNewHandlerRejectsNilResolver(t *testing.T) {
	_, err := NewHandler(nil, testSecret)
	if err == nil {
		t.Fatal("expected error for nil resolver")
	}
}

func TestWhoamiHappyPath(t *testing.T) {
	expiry := time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)
	resolver := &fakeResolver{
		result: auth.DelegatedAccessResult{
			AccessToken:          "gho_fresh_xyz",
			ProviderAccessExpiry: expiry,
			Scopes:               []string{"repo", "read:user"},
		},
	}
	srv, cleanup := newTestServer(t, resolver, testSecret)
	defer cleanup()

	resp := doWhoami(t, srv, testSecret, `{"subject":"github|123"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d want 200; body=%s", resp.StatusCode, body)
	}
	var payload map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload["access_token"] != "gho_fresh_xyz" {
		t.Errorf("access_token: got %v", payload["access_token"])
	}
	if payload["token_type"] != "bearer" {
		t.Errorf("token_type: got %v", payload["token_type"])
	}
	if payload["expires_at"] != "2030-01-02T03:04:05Z" {
		t.Errorf("expires_at: got %v", payload["expires_at"])
	}
	gotScopes, _ := payload["scopes"].([]any)
	if len(gotScopes) != 2 || gotScopes[0] != "repo" || gotScopes[1] != "read:user" {
		t.Errorf("scopes: got %v want [repo read:user]", payload["scopes"])
	}
	if resolver.gotSubject != "github|123" {
		t.Errorf("subject forwarded: got %q", resolver.gotSubject)
	}
}

func TestWhoamiMissingAuth(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	resp := doWhoamiRaw(t, srv, "", `{"subject":"x"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

func TestWhoamiBadSecret(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	// Same length as testSecret but different bytes -- exercises
	// ConstantTimeCompare's mismatch branch rather than the length guard.
	badSecret := strings.Repeat("z", len(testSecret))
	resp := doWhoami(t, srv, badSecret, `{"subject":"x"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status: got %d want 401", resp.StatusCode)
	}
}

func TestWhoamiSubjectNotFound(t *testing.T) {
	resolver := &fakeResolver{err: auth.ErrSubjectNotFound}
	srv, cleanup := newTestServer(t, resolver, testSecret)
	defer cleanup()
	resp := doWhoami(t, srv, testSecret, `{"subject":"unknown"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status: got %d want 404", resp.StatusCode)
	}
}

func TestWhoamiUpstreamError(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("provider blew up")}
	srv, cleanup := newTestServer(t, resolver, testSecret)
	defer cleanup()
	resp := doWhoami(t, srv, testSecret, `{"subject":"x"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502", resp.StatusCode)
	}
}

func TestWhoamiBadBody(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	resp := doWhoami(t, srv, testSecret, `not-json`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestWhoamiMissingSubject(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	resp := doWhoami(t, srv, testSecret, `{"subject":""}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestWhoamiUnknownFieldsRejected(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	resp := doWhoami(t, srv, testSecret, `{"subject":"x","sneaky":"y"}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400", resp.StatusCode)
	}
}

func TestWhoamiOversizedBody(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{
		result: auth.DelegatedAccessResult{AccessToken: "ok"},
	}, testSecret)
	defer cleanup()
	// A 5KB body exceeds the 4KB limit; the request fails before reaching
	// the resolver.
	pad := strings.Repeat("a", 5*1024)
	body := `{"subject":"` + pad + `"}`
	resp := doWhoami(t, srv, testSecret, body)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status: got %d want 400 for oversized body", resp.StatusCode)
	}
}

func TestWhoamiGETRejected(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{}, testSecret)
	defer cleanup()
	req, _ := http.NewRequest("GET", srv.URL+"/internal/v1/whoami", nil)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("status: got %d want 405", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); !strings.HasPrefix(got, "application/json") {
		t.Errorf("content-type: got %q want application/json", got)
	}
	if got := resp.Header.Get("Allow"); got != "POST" {
		t.Errorf("Allow header: got %q want POST", got)
	}
	var body map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["error"] != "method_not_allowed" {
		t.Errorf("error code: got %q want method_not_allowed", body["error"])
	}
}

// TestWhoamiTrailingJSONRejected verifies that a request body with extra
// tokens after the JSON object is rejected as invalid_body. Without this
// check, json.Decoder would silently accept the first object and ignore
// the rest -- letting a caller smuggle additional payload.
//
// Each case exercises a different trailing-data shape. The closing-bracket
// case in particular is the one that motivated the cycle-3 review fix:
// dec.More() returns false for a stray "]" because it does not begin a
// new JSON value, so the second-Decode-requires-io.EOF strategy is needed
// to catch it.
func TestWhoamiTrailingJSONRejected(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{"second object", `{"subject":"alice"}{"subject":"mallory"}`},
		{"trailing bracket", `{"subject":"alice"}]`},
		{"trailing brace", `{"subject":"alice"}}`},
		{"trailing array", `{"subject":"alice"}[1]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, cleanup := newTestServer(t, &fakeResolver{
				result: auth.DelegatedAccessResult{AccessToken: "tok"},
			}, testSecret)
			defer cleanup()
			req, _ := http.NewRequest("POST", srv.URL+"/internal/v1/whoami", strings.NewReader(tc.body))
			req.Header.Set("Authorization", "Bearer "+testSecret)
			req.Header.Set("Content-Type", "application/json")
			resp, err := srv.Client().Do(req)
			if err != nil {
				t.Fatalf("Do: %v", err)
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status: got %d want 400 for trailing JSON", resp.StatusCode)
			}
			var env map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if env["error"] != "invalid_body" {
				t.Errorf("error code: got %q want invalid_body", env["error"])
			}
		})
	}
}

// TestWhoamiRotationFailedMaps502 verifies that auth.ErrRotationFailed is
// surfaced as a 502 with a dedicated error code, distinct from a generic
// upstream_failure.
func TestWhoamiRotationFailedMaps502(t *testing.T) {
	srv, cleanup := newTestServer(t, &fakeResolver{err: auth.ErrRotationFailed}, testSecret)
	defer cleanup()
	body := `{"subject":"alice"}`
	req, _ := http.NewRequest("POST", srv.URL+"/internal/v1/whoami", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status: got %d want 502", resp.StatusCode)
	}
	var env map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if env["error"] != "rotation_failed" {
		t.Errorf("error code: got %q want rotation_failed", env["error"])
	}
}

// TestIsLoopback covers the helper directly because relying on httptest to
// produce non-loopback RemoteAddr is impractical.
func TestIsLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"127.0.0.1:1234", true},
		{"[::1]:1234", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"10.0.0.5:1234", false},
		{"192.168.1.1:80", false},
		{"example.com:80", false},
		{"", false},
	}
	for _, c := range cases {
		if got := isLoopback(c.addr); got != c.want {
			t.Errorf("isLoopback(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestWhoamiNonLoopbackRejected covers the in-handler defense-in-depth check
// by invoking the handler directly with a non-loopback RemoteAddr.
func TestWhoamiNonLoopbackRejected(t *testing.T) {
	h, err := NewHandler(&fakeResolver{
		result: auth.DelegatedAccessResult{AccessToken: "ok"},
	}, testSecret)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	req := httptest.NewRequest("POST", "/internal/v1/whoami", strings.NewReader(`{"subject":"x"}`))
	req.Header.Set("Authorization", "Bearer "+testSecret)
	req.RemoteAddr = "10.20.30.40:5555"
	rr := httptest.NewRecorder()
	h.Whoami(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status: got %d want 403", rr.Code)
	}
}

func TestAuthFailures(t *testing.T) {
	reader := &fakeFailureReader{failures: []authaudit.Event{
		{
			Timestamp:  time.Date(2026, 6, 13, 1, 2, 3, 0, time.UTC),
			Event:      "oauth_audit",
			Phase:      "rotation",
			Provider:   "github",
			Result:     "failure",
			ErrorClass: "provider_rejected",
			OAuthError: "bad_refresh_token",
			Message:    "provider token rotation rejected",
			TokenHash:  "12345678",
		},
		{
			Timestamp:  time.Date(2026, 6, 13, 1, 1, 3, 0, time.UTC),
			Event:      "oauth_audit",
			Phase:      "callback",
			Provider:   "oidc",
			Result:     "failure",
			ErrorClass: "access_denied",
			OAuthError: "access_denied",
			Message:    "provider authorization callback rejected",
		},
	}}
	h, err := NewHandler(&fakeResolver{}, testSecret, WithFailureReader(reader))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	mux := http.NewServeMux()
	h.RegisterRoutes(mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/internal/v1/auth/failures?limit=1", nil)
	req.Header.Set("Authorization", "Bearer "+testSecret)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("status: got %d, want 200; body=%s", resp.StatusCode, body)
	}
	var payload struct {
		Failures []authaudit.Event `json:"failures"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if len(payload.Failures) != 1 {
		t.Fatalf("failure count: got %d, want 1", len(payload.Failures))
	}
	if payload.Failures[0].OAuthError != "bad_refresh_token" {
		t.Errorf("oauth_error: got %q", payload.Failures[0].OAuthError)
	}
	if strings.Contains(mustJSON(t, payload), `"refresh_token":`) {
		t.Fatal("diagnostic response contains a raw refresh_token field")
	}
}

func TestAuthFailuresErrors(t *testing.T) {
	cases := []struct {
		name       string
		method     string
		auth       string
		target     string
		withReader bool
		wantStatus int
		wantError  string
	}{
		{
			name:       "method rejected",
			method:     http.MethodPost,
			auth:       "Bearer " + testSecret,
			target:     "/internal/v1/auth/failures",
			withReader: true,
			wantStatus: http.StatusMethodNotAllowed,
			wantError:  "method_not_allowed",
		},
		{
			name:       "authorization required",
			method:     http.MethodGet,
			target:     "/internal/v1/auth/failures",
			withReader: true,
			wantStatus: http.StatusUnauthorized,
			wantError:  "invalid_authorization",
		},
		{
			name:       "reader unavailable",
			method:     http.MethodGet,
			auth:       "Bearer " + testSecret,
			target:     "/internal/v1/auth/failures",
			wantStatus: http.StatusServiceUnavailable,
			wantError:  "diagnostics_unavailable",
		},
		{
			name:       "limit rejected",
			method:     http.MethodGet,
			auth:       "Bearer " + testSecret,
			target:     "/internal/v1/auth/failures?limit=101",
			withReader: true,
			wantStatus: http.StatusBadRequest,
			wantError:  "invalid_limit",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var opts []HandlerOption
			if tc.withReader {
				opts = append(opts, WithFailureReader(&fakeFailureReader{}))
			}
			h, err := NewHandler(&fakeResolver{}, testSecret, opts...)
			if err != nil {
				t.Fatalf("NewHandler: %v", err)
			}
			req := httptest.NewRequest(tc.method, tc.target, nil)
			req.RemoteAddr = "127.0.0.1:1234"
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}
			rec := httptest.NewRecorder()
			h.AuthFailures(rec, req)
			if rec.Code != tc.wantStatus {
				t.Fatalf("status: got %d, want %d", rec.Code, tc.wantStatus)
			}
			var envelope map[string]string
			if err := json.NewDecoder(rec.Body).Decode(&envelope); err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if envelope["error"] != tc.wantError {
				t.Errorf("error: got %q, want %q", envelope["error"], tc.wantError)
			}
		})
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	return string(data)
}

// doWhoami issues a properly authenticated POST request. It centralizes
// boilerplate so individual test cases stay focused on the assertion.
func doWhoami(t *testing.T, srv *httptest.Server, secret, body string) *http.Response {
	t.Helper()
	return doWhoamiRaw(t, srv, "Bearer "+secret, body)
}

func doWhoamiRaw(t *testing.T, srv *httptest.Server, authzHeader, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("POST", srv.URL+"/internal/v1/whoami", strings.NewReader(body))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if authzHeader != "" {
		req.Header.Set("Authorization", authzHeader)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	return resp
}
