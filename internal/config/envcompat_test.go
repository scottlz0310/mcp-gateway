package config

import (
	"os"
	"strings"
	"testing"
)

// TestResolveOAuthEnv_PrefersCanonical verifies the canonical env var wins
// when both canonical and legacy are set.
func TestResolveOAuthEnv_PrefersCanonical(t *testing.T) {
	logBuf := captureLogs(t)
	resetLegacyEnvWarnedForTest()
	t.Setenv("OAUTH_CLIENT_ID", "new")
	t.Setenv("GITHUB_MCP_CLIENT_ID", "old")

	v, ok := ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	if !ok || v != "new" {
		t.Fatalf("got %q ok=%v, want \"new\" ok=true", v, ok)
	}
	out := logBuf.String()
	if !strings.Contains(out, "GITHUB_MCP_CLIENT_ID") || !strings.Contains(out, "ignored") {
		t.Errorf("expected ignored-legacy warning, got: %s", out)
	}
}

// TestResolveOAuthEnv_FallsBackToLegacy verifies the legacy var is used and
// warned about when only it is set.
func TestResolveOAuthEnv_FallsBackToLegacy(t *testing.T) {
	logBuf := captureLogs(t)
	resetLegacyEnvWarnedForTest()
	_ = os.Unsetenv("OAUTH_CLIENT_ID")
	t.Setenv("GITHUB_MCP_CLIENT_ID", "legacy-id")

	v, ok := ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	if !ok || v != "legacy-id" {
		t.Fatalf("got %q ok=%v, want \"legacy-id\" ok=true", v, ok)
	}
	out := logBuf.String()
	if !strings.Contains(out, "deprecated") || !strings.Contains(out, "GITHUB_MCP_CLIENT_ID") {
		t.Errorf("expected deprecation warning, got: %s", out)
	}
}

// TestResolveOAuthEnv_NeitherSet returns ok=false when neither var is set.
func TestResolveOAuthEnv_NeitherSet(t *testing.T) {
	resetLegacyEnvWarnedForTest()
	_ = os.Unsetenv("OAUTH_CLIENT_ID")
	_ = os.Unsetenv("GITHUB_MCP_CLIENT_ID")

	v, ok := ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	if ok || v != "" {
		t.Fatalf("got %q ok=%v, want \"\" ok=false", v, ok)
	}
}

// TestResolveOAuthEnv_WarnOnce verifies the deprecation warning is emitted at
// most once per legacy variable even across repeated lookups.
func TestResolveOAuthEnv_WarnOnce(t *testing.T) {
	logBuf := captureLogs(t)
	resetLegacyEnvWarnedForTest()
	_ = os.Unsetenv("OAUTH_CLIENT_ID")
	t.Setenv("GITHUB_MCP_CLIENT_ID", "legacy-id")

	for i := 0; i < 3; i++ {
		ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	}
	count := strings.Count(logBuf.String(), "GITHUB_MCP_CLIENT_ID")
	// Each warning line mentions the legacy var twice (once in the message
	// hint, once in the structured field). Allow up to two occurrences total.
	if count > 2 {
		t.Errorf("expected the warning to be emitted once, but legacy var was logged %d times: %s", count, logBuf.String())
	}
	if count == 0 {
		t.Errorf("expected at least one deprecation warning, got none")
	}
}

// TestResolveOAuthEnv_EmptyTreatedAsUnset verifies an empty-string env var is
// treated as unset.
func TestResolveOAuthEnv_EmptyTreatedAsUnset(t *testing.T) {
	resetLegacyEnvWarnedForTest()
	t.Setenv("OAUTH_CLIENT_ID", "   ")
	t.Setenv("GITHUB_MCP_CLIENT_ID", "legacy")

	v, ok := ResolveOAuthEnv("OAUTH_CLIENT_ID", "GITHUB_MCP_CLIENT_ID")
	if !ok || v != "legacy" {
		t.Fatalf("expected fallback to legacy, got %q ok=%v", v, ok)
	}
}
