package authaudit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDefaultPath(t *testing.T) {
	cases := []struct {
		name    string
		goos    string
		env     map[string]string
		home    string
		want    string
		wantErr bool
	}{
		{
			name: "windows local app data",
			goos: "windows",
			env:  map[string]string{"LOCALAPPDATA": `C:\Users\alice\AppData\Local`},
			want: `C:\Users\alice\AppData\Local\mcp-gateway\logs\auth-audit.jsonl`,
		},
		{
			name: "linux xdg state",
			goos: "linux",
			env:  map[string]string{"XDG_STATE_HOME": "/state"},
			want: "/state/mcp-gateway/logs/auth-audit.jsonl",
		},
		{
			name: "linux home fallback",
			goos: "linux",
			home: "/home/alice",
			want: "/home/alice/.local/state/mcp-gateway/logs/auth-audit.jsonl",
		},
		{
			name: "macOS logs",
			goos: "darwin",
			home: "/Users/alice",
			want: "/Users/alice/Library/Logs/mcp-gateway/auth-audit.jsonl",
		},
		{
			name:    "windows missing local app data",
			goos:    "windows",
			wantErr: true,
		},
		{
			name:    "linux relative xdg state",
			goos:    "linux",
			env:     map[string]string{"XDG_STATE_HOME": "relative"},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			getenv := func(key string) string {
				return tc.env[key]
			}
			userHome := func() (string, error) {
				return tc.home, nil
			}
			got, err := defaultPath(tc.goos, getenv, userHome)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("defaultPath: %v", err)
			}
			if got != tc.want {
				t.Errorf("path: got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestResolvePathRejectsRelativeAndGitWorktree(t *testing.T) {
	if _, err := ResolvePath("logs/auth-audit.jsonl"); err == nil {
		t.Fatal("expected relative path rejection")
	}

	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	path := filepath.Join(root, "logs", "auth-audit.jsonl")
	if _, err := ResolvePath(path); err == nil {
		t.Fatal("expected Git worktree path rejection")
	}
}

func TestRecorderRejectsSymlinkIntoGitWorktree(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires environment-specific privileges")
	}
	worktree := t.TempDir()
	if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o700); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}
	target := filepath.Join(worktree, "auth-audit.jsonl")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	link := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	_, err := New(Config{
		Path:            link,
		MaxSizeBytes:    1 << 20,
		MaxBackups:      2,
		MaxAge:          24 * time.Hour,
		FailureCapacity: 10,
	})
	if err == nil {
		t.Fatal("expected symlink into Git worktree rejection")
	}
}

func TestFromEnvironment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	t.Setenv("MCP_GATEWAY_AUTH_AUDIT_LOG_PATH", path)
	t.Setenv("MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB", "12")
	t.Setenv("MCP_GATEWAY_AUTH_AUDIT_MAX_BACKUPS", "7")
	t.Setenv("MCP_GATEWAY_AUTH_AUDIT_MAX_AGE_DAYS", "45")

	cfg, err := FromEnvironment()
	if err != nil {
		t.Fatalf("FromEnvironment: %v", err)
	}
	if cfg.Path != path {
		t.Errorf("path: got %q, want %q", cfg.Path, path)
	}
	if cfg.MaxSizeBytes != 12*1024*1024 || cfg.MaxBackups != 7 || cfg.MaxAge != 45*24*time.Hour {
		t.Errorf("config: got %#v", cfg)
	}

	t.Setenv("MCP_GATEWAY_AUTH_AUDIT_MAX_SIZE_MB", "invalid")
	if _, err := FromEnvironment(); err == nil {
		t.Fatal("expected invalid size error")
	}
}

func TestRecorderWritesJSONLinesAndRecentFailures(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	recorder, err := New(Config{
		Path:            path,
		MaxSizeBytes:    1 << 20,
		MaxBackups:      2,
		MaxAge:          24 * time.Hour,
		FailureCapacity: 2,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = recorder.Close() }()

	events := []Event{
		{Phase: "authorize", Provider: "github", Result: "success", Message: "authorization started"},
		{Phase: "callback", Provider: "github", Result: "failure", ErrorClass: "invalid_grant", OAuthError: "access_denied", HTTPStatus: 400, Message: "provider rejected authorization"},
		{Phase: "refresh", Provider: "github", Result: "failure", ErrorClass: "token_expired", Message: "refresh token expired"},
		{Phase: "rotation", Provider: "github", Result: "failure", ErrorClass: "provider_unavailable", TokenHash: "12345678", Message: "provider rotation unavailable"},
	}
	for _, event := range events {
		if err := recorder.Record(event); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	if err := recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatalf("Stat: %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Errorf("permissions: got %o, want 600", got)
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != len(events) {
		t.Fatalf("line count: got %d, want %d", len(lines), len(events))
	}
	for _, line := range lines {
		var event Event
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("invalid JSON line %q: %v", line, err)
		}
		if event.Event != auditEventName {
			t.Errorf("event: got %q, want %q", event.Event, auditEventName)
		}
		if event.Timestamp.IsZero() {
			t.Error("timestamp is zero")
		}
	}

	failures := recorder.RecentFailures()
	if len(failures) != 2 {
		t.Fatalf("failure count: got %d, want 2", len(failures))
	}
	if failures[0].Phase != "rotation" || failures[1].Phase != "refresh" {
		t.Errorf("failures are not newest-first: %#v", failures)
	}
}

func TestRecorderRotatesAndEnforcesBackupLimit(t *testing.T) {
	baseTime := time.Date(2026, 6, 13, 1, 2, 3, 0, time.UTC)
	now := baseTime
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	recorder, err := newRecorder(Config{
		Path:            path,
		MaxSizeBytes:    180,
		MaxBackups:      2,
		MaxAge:          24 * time.Hour,
		FailureCapacity: 10,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	defer func() { _ = recorder.Close() }()

	for index := 0; index < 8; index++ {
		now = now.Add(time.Second)
		if err := recorder.Record(Event{
			Phase:    "callback",
			Provider: "github",
			Result:   "failure",
			Message:  strings.Repeat("x", 80),
		}); err != nil {
			t.Fatalf("Record %d: %v", index, err)
		}
	}

	ext := filepath.Ext(path)
	stem := strings.TrimSuffix(path, ext)
	backups, err := filepath.Glob(stem + ".*" + ext)
	if err != nil {
		t.Fatalf("Glob: %v", err)
	}
	if len(backups) != 2 {
		t.Fatalf("backup count: got %d, want 2 (%v)", len(backups), backups)
	}
}

func TestRecorderRemovesExpiredBackups(t *testing.T) {
	now := time.Date(2026, 6, 13, 1, 2, 3, 0, time.UTC)
	dir := t.TempDir()
	path := filepath.Join(dir, "auth-audit.jsonl")
	oldBackup := filepath.Join(dir, "auth-audit.20250101T000000.000000000Z.000.jsonl")
	if err := os.WriteFile(oldBackup, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	oldTime := now.Add(-48 * time.Hour)
	if err := os.Chtimes(oldBackup, oldTime, oldTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	recorder, err := newRecorder(Config{
		Path:            path,
		MaxSizeBytes:    1 << 20,
		MaxBackups:      5,
		MaxAge:          24 * time.Hour,
		FailureCapacity: 10,
	}, func() time.Time { return now })
	if err != nil {
		t.Fatalf("newRecorder: %v", err)
	}
	defer func() { _ = recorder.Close() }()

	if _, err := os.Stat(oldBackup); !os.IsNotExist(err) {
		t.Fatalf("expired backup still exists: %v", err)
	}
}

func TestRecorderConcurrentWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "auth-audit.jsonl")
	recorder, err := New(Config{
		Path:            path,
		MaxSizeBytes:    1 << 20,
		MaxBackups:      2,
		MaxAge:          24 * time.Hour,
		FailureCapacity: 100,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = recorder.Close() }()

	const writes = 50
	var wg sync.WaitGroup
	wg.Add(writes)
	for index := 0; index < writes; index++ {
		go func() {
			defer wg.Done()
			if err := recorder.Record(Event{
				Phase:    "authorize",
				Provider: "github",
				Result:   "success",
				Message:  "authorization started",
			}); err != nil {
				t.Errorf("Record: %v", err)
			}
		}()
	}
	wg.Wait()
	if err := recorder.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != writes {
		t.Fatalf("line count: got %d, want %d", len(lines), writes)
	}
	for _, line := range lines {
		if !json.Valid([]byte(line)) {
			t.Fatalf("invalid JSON line: %q", line)
		}
	}
}

func TestEventCannotSerializeSecretsByConstruction(t *testing.T) {
	event := Event{
		Phase:      "callback",
		Provider:   "github",
		Result:     "failure",
		ErrorClass: "provider_rejected",
		Message:    "provider rejected authorization",
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	for _, forbidden := range []string{"access_token", "refresh_token", "authorization_code", "client_secret", "state"} {
		if strings.Contains(string(data), forbidden) {
			t.Errorf("serialized event contains forbidden field %q: %s", forbidden, data)
		}
	}
}
