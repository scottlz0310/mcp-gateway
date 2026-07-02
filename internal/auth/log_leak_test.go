package auth

// Regression tests for issue #193 (token log-leak audit): raw token values
// (provider access tokens, gateway JWTs, refresh tokens) must never appear in
// log output. Logging helpers may only emit sha256-based fingerprints.
// See docs/token-log-audit.md and CONTRIBUTING.md "Logging & Secrets".

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/auth/provider"
	"github.com/scottlz0310/mcp-gateway/internal/authaudit"
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

// TestBuiltinFlowLogsDoNotLeakTokens runs the full builtin authorization-code
// flow plus a refresh_token grant with the audit recorder enabled, then
// asserts that none of the secrets involved appear in the captured log output.
func TestBuiltinFlowLogsDoNotLeakTokens(t *testing.T) {
	logs := captureLogs(t)

	const ghAccessToken = "gho_RAW_PROVIDER_TOKEN_MUST_NOT_LOG"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	recorder, err := authaudit.New(authaudit.Config{
		Path:            filepath.Join(t.TempDir(), "audit.log"),
		MaxSizeBytes:    1 << 20,
		MaxBackups:      1,
		MaxAge:          time.Hour,
		FailureCapacity: 8,
	})
	if err != nil {
		t.Fatalf("authaudit.New: %v", err)
	}
	t.Cleanup(func() { _ = recorder.Close() })

	p := &provider.Mock{
		NameValue:     "builtin",
		ClientIDValue: "builtin-client-id",
		ScopesValue:   "read:user,user:email",
		ExchangeCodeFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
			return provider.TokenResponse{AccessToken: ghAccessToken}, nil
		},
		ValidateFunc: func(_ context.Context, _ string) (provider.Identity, error) {
			return provider.Identity{Subject: "alice"}, nil
		},
	}
	h, err := NewHandler(Config{
		BaseURL:        "http://localhost:8080",
		SessionTTL:     10 * time.Minute,
		CacheTTL:       5 * time.Minute,
		ExpiresIn:      90 * 24 * time.Hour,
		OIDCPrivateKey: key,
	}, p, WithAuditRecorder(recorder))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	resp, accessToken := runBuiltinFullFlow(t, h, "alice")
	refreshToken, _ := resp["refresh_token"].(string)
	if accessToken == "" || refreshToken == "" {
		t.Fatalf("flow did not issue tokens: access=%q refresh=%q", accessToken, refreshToken)
	}

	refreshBody := "grant_type=refresh_token&refresh_token=" + url.QueryEscape(refreshToken)
	refreshReq := httptest.NewRequest(http.MethodPost, "/token", strings.NewReader(refreshBody))
	refreshReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRec := httptest.NewRecorder()
	h.Token(refreshRec, refreshReq)
	if refreshRec.Code != http.StatusOK {
		t.Fatalf("refresh: got %d; body=%s", refreshRec.Code, refreshRec.Body.String())
	}
	var refreshResp map[string]any
	if err := json.NewDecoder(refreshRec.Body).Decode(&refreshResp); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	newAccessToken, _ := refreshResp["access_token"].(string)
	newRefreshToken, _ := refreshResp["refresh_token"].(string)
	if newAccessToken == "" || newRefreshToken == "" {
		t.Fatalf("refresh did not rotate tokens: access=%q refresh=%q", newAccessToken, newRefreshToken)
	}

	out := logs.String()
	if !strings.Contains(out, "oauth audit") {
		t.Fatalf("expected audit log lines to be captured; got: %s", out)
	}
	secrets := map[string]string{
		"provider access token": ghAccessToken,
		"gateway access token":  accessToken,
		"refresh token":         refreshToken,
		"rotated access token":  newAccessToken,
		"rotated refresh token": newRefreshToken,
	}
	for name, secret := range secrets {
		if strings.Contains(out, secret) {
			t.Errorf("log output contains raw %s", name)
		}
	}
}

// TestRotationLogsDoNotLeakTokens covers the GitHub rotation paths in
// EnsureFreshAccessTokenForSubject: both the rotation_failed and the
// "github access token rotated" log lines must identify tokens only via
// tokenFingerprint, never raw values.
func TestRotationLogsDoNotLeakTokens(t *testing.T) {
	const (
		oldBearer      = "tok-OLD-BEARER-MUST-NOT-LOG"
		oldRefresh     = "refresh-OLD-MUST-NOT-LOG"
		rotatedAccess  = "gho_ROTATED-MUST-NOT-LOG"
		rotatedRefresh = "ghr_ROTATED-MUST-NOT-LOG"
	)
	cases := []struct {
		name        string
		refreshFunc func(context.Context, string) (provider.TokenResponse, error)
		checkErr    func(*testing.T, error)
		wantLogLine string
	}{
		{
			name: "permanent failure",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{}, errors.New("bad_refresh_token")
			},
			checkErr: func(t *testing.T, err error) {
				if !errors.Is(err, ErrRotationFailed) {
					t.Fatalf("err=%v want ErrRotationFailed", err)
				}
			},
			wantLogLine: "rotation_failed",
		},
		{
			name: "success",
			refreshFunc: func(_ context.Context, _ string) (provider.TokenResponse, error) {
				return provider.TokenResponse{
					AccessToken:          rotatedAccess,
					RefreshToken:         rotatedRefresh,
					AccessTokenExpiresIn: 8 * time.Hour,
					Scopes:               []string{"repo", "user"},
				}, nil
			},
			checkErr: func(t *testing.T, err error) {
				if err != nil {
					t.Fatalf("err=%v want nil", err)
				}
			},
			wantLogLine: "github access token rotated",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			p := &provider.Mock{
				NameValue:        "github",
				ScopesValue:      "repo,user",
				RefreshTokenFunc: tc.refreshFunc,
			}
			h := newDelegatedTestHandler(t, p, 5*time.Minute)
			h.store.CacheToken(oldBearer, "alice", "http://localhost:8080/mcp")
			h.store.RecordProviderRefresh(oldBearer, oldRefresh, time.Now().Add(30*time.Second))

			_, err := h.EnsureFreshAccessTokenForSubject(context.Background(), "alice")
			tc.checkErr(t, err)

			out := logs.String()
			if !strings.Contains(out, tc.wantLogLine) {
				t.Fatalf("expected %q log line; got: %s", tc.wantLogLine, out)
			}
			for _, secret := range []string{oldBearer, oldRefresh, rotatedAccess, rotatedRefresh} {
				if strings.Contains(out, secret) {
					t.Errorf("log output contains raw token %q", secret)
				}
			}
		})
	}
}
