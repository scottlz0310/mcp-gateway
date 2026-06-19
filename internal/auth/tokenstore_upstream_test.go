package auth

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// upstreamTokenStoreContract はすべての UpstreamTokenStore 実装が満たすべき
// 共通コントラクトテストを実行する。
func upstreamTokenStoreContract(t *testing.T, newStore func(t *testing.T) UpstreamTokenStore) {
	t.Helper()

	t.Run("Save and Lookup", func(t *testing.T) {
		s := newStore(t)
		rec := UpstreamTokenRecord{
			Issuer:       "https://as.example.com",
			AccessToken:  "at-abc",
			RefreshToken: "rt-abc",
			Scope:        "openid profile",
			ExpiresAt:    time.Now().Add(time.Hour),
		}
		if err := s.Save("user1", "route-a", rec); err != nil {
			t.Fatalf("Save: %v", err)
		}
		got, ok := s.Lookup("user1", "route-a")
		if !ok {
			t.Fatal("Lookup: expected record, got not-found")
		}
		if got.AccessToken != rec.AccessToken {
			t.Errorf("AccessToken: got %q, want %q", got.AccessToken, rec.AccessToken)
		}
		if got.Subject != "user1" {
			t.Errorf("Subject: got %q, want user1", got.Subject)
		}
		if got.RouteName != "route-a" {
			t.Errorf("RouteName: got %q, want route-a", got.RouteName)
		}
	})

	t.Run("Lookup absent returns false", func(t *testing.T) {
		s := newStore(t)
		_, ok := s.Lookup("nobody", "no-route")
		if ok {
			t.Fatal("Lookup: expected not-found for absent key, got found")
		}
	})

	t.Run("Lookup expired returns false", func(t *testing.T) {
		s := newStore(t)
		rec := UpstreamTokenRecord{
			Issuer:      "https://as.example.com",
			AccessToken: "at-expired",
			ExpiresAt:   time.Now().Add(-time.Second), // already expired
		}
		if err := s.Save("user2", "route-b", rec); err != nil {
			t.Fatalf("Save: %v", err)
		}
		_, ok := s.Lookup("user2", "route-b")
		if ok {
			t.Fatal("Lookup: expected not-found for expired entry, got found")
		}
	})

	t.Run("ExpiresAt zero is permanent (never swept)", func(t *testing.T) {
		s := newStore(t)
		rec := UpstreamTokenRecord{
			Issuer:      "https://as.example.com",
			AccessToken: "at-permanent",
			ExpiresAt:   time.Time{}, // zero = permanent
		}
		if err := s.Save("user3", "route-c", rec); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := s.Sweep(); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		_, ok := s.Lookup("user3", "route-c")
		if !ok {
			t.Fatal("Lookup: permanent entry must survive Sweep")
		}
	})

	t.Run("Sweep removes expired entries", func(t *testing.T) {
		s := newStore(t)
		expired := UpstreamTokenRecord{
			Issuer:      "https://as.example.com",
			AccessToken: "at-sweep",
			ExpiresAt:   time.Now().Add(-time.Second),
		}
		live := UpstreamTokenRecord{
			Issuer:      "https://as.example.com",
			AccessToken: "at-live",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		if err := s.Save("user4", "route-d", expired); err != nil {
			t.Fatalf("Save expired: %v", err)
		}
		if err := s.Save("user5", "route-e", live); err != nil {
			t.Fatalf("Save live: %v", err)
		}
		if err := s.Sweep(); err != nil {
			t.Fatalf("Sweep: %v", err)
		}
		if _, ok := s.Lookup("user4", "route-d"); ok {
			t.Error("expired entry should be removed by Sweep")
		}
		if _, ok := s.Lookup("user5", "route-e"); !ok {
			t.Error("live entry should survive Sweep")
		}
	})

	t.Run("Delete removes entry", func(t *testing.T) {
		s := newStore(t)
		rec := UpstreamTokenRecord{
			Issuer:      "https://as.example.com",
			AccessToken: "at-delete",
			ExpiresAt:   time.Now().Add(time.Hour),
		}
		if err := s.Save("user6", "route-f", rec); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if err := s.Delete("user6", "route-f"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if _, ok := s.Lookup("user6", "route-f"); ok {
			t.Error("Lookup: entry should be absent after Delete")
		}
	})

	t.Run("Keys are independent per (subject, routeName)", func(t *testing.T) {
		s := newStore(t)
		if err := s.Save("user7", "route-g", UpstreamTokenRecord{
			Issuer: "a", AccessToken: "token-a", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save user7/route-g: %v", err)
		}
		if err := s.Save("user7", "route-h", UpstreamTokenRecord{
			Issuer: "b", AccessToken: "token-b", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save user7/route-h: %v", err)
		}
		if err := s.Save("user8", "route-g", UpstreamTokenRecord{
			Issuer: "c", AccessToken: "token-c", ExpiresAt: time.Now().Add(time.Hour),
		}); err != nil {
			t.Fatalf("Save user8/route-g: %v", err)
		}
		r1, _ := s.Lookup("user7", "route-g")
		r2, _ := s.Lookup("user7", "route-h")
		r3, _ := s.Lookup("user8", "route-g")
		if r1.AccessToken != "token-a" || r2.AccessToken != "token-b" || r3.AccessToken != "token-c" {
			t.Errorf("Lookup returned wrong tokens: %q %q %q", r1.AccessToken, r2.AccessToken, r3.AccessToken)
		}
	})
}

func TestMemUpstreamTokenStore_Contract(t *testing.T) {
	upstreamTokenStoreContract(t, func(t *testing.T) UpstreamTokenStore {
		t.Helper()
		return NewMemUpstreamTokenStore()
	})
}

func TestFileUpstreamTokenStore_Contract(t *testing.T) {
	upstreamTokenStoreContract(t, func(t *testing.T) UpstreamTokenStore {
		t.Helper()
		dir := t.TempDir()
		s, err := NewFileUpstreamTokenStore(filepath.Join(dir, "upstream_tokens.json"))
		if err != nil {
			t.Fatalf("NewFileUpstreamTokenStore: %v", err)
		}
		return s
	})
}

func TestFileUpstreamTokenStore_Persistence(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")

	s1, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore (first): %v", err)
	}
	rec := UpstreamTokenRecord{
		Issuer:       "https://as.example.com",
		AccessToken:  "at-persist",
		RefreshToken: "rt-persist",
		Scope:        "openid",
		ExpiresAt:    time.Now().Add(time.Hour).Truncate(time.Second),
	}
	if err := s1.Save("user-p", "route-p", rec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 別インスタンスで同じファイルを開き直す
	s2, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore (second): %v", err)
	}
	got, ok := s2.Lookup("user-p", "route-p")
	if !ok {
		t.Fatal("Lookup (second instance): expected record, got not-found")
	}
	if got.AccessToken != rec.AccessToken {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, rec.AccessToken)
	}
	if got.RefreshToken != rec.RefreshToken {
		t.Errorf("RefreshToken: got %q, want %q", got.RefreshToken, rec.RefreshToken)
	}
}

func TestFileUpstreamTokenStore_StartupSweep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")

	s1, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore (first): %v", err)
	}
	expired := UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-stale",
		ExpiresAt:   time.Now().Add(-time.Minute), // already expired
	}
	live := UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-live",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := s1.Save("user-s1", "route-s", expired); err != nil {
		t.Fatalf("Save expired: %v", err)
	}
	if err := s1.Save("user-s2", "route-s", live); err != nil {
		t.Fatalf("Save live: %v", err)
	}

	// 再起動 → startup sweep で期限切れエントリが除去されるはず
	s2, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore (second): %v", err)
	}
	if _, ok := s2.Lookup("user-s1", "route-s"); ok {
		t.Error("startup sweep should have removed expired entry")
	}
	if _, ok := s2.Lookup("user-s2", "route-s"); !ok {
		t.Error("live entry must survive startup sweep")
	}
}

func TestFileUpstreamTokenStore_IdentityNotInJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")

	s, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore: %v", err)
	}
	if err := s.Save("alice", "my-route", UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-secret",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	content := string(raw)
	if strings.Contains(content, "alice") {
		t.Error("subject 'alice' must not appear in the JSON file")
	}
	if strings.Contains(content, "my-route") {
		t.Error("routeName 'my-route' must not appear in the JSON file")
	}

	// キーは 64 文字の hex 文字列（sha256）であること
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("JSON parse: %v", err)
	}
	for k := range m {
		if len(k) != 64 {
			t.Errorf("key %q is not a 64-char sha256 hex string", k)
		}
	}
}

func TestFileUpstreamTokenStore_NonExistentFileOK(t *testing.T) {
	dir := t.TempDir()
	s, err := NewFileUpstreamTokenStore(filepath.Join(dir, "does_not_exist.json"))
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore with non-existent file: %v", err)
	}
	if _, ok := s.Lookup("nobody", "no-route"); ok {
		t.Error("expected empty store")
	}
}

func TestFileUpstreamTokenStore_ParentDirNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent-dir", "upstream_tokens.json")
	_, err := NewFileUpstreamTokenStore(path)
	if err == nil {
		t.Fatal("expected error when parent directory does not exist, got nil")
	}
}

func TestFileUpstreamTokenStore_LoadInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := NewFileUpstreamTokenStore(path)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestFileUpstreamTokenStore_SaveRollbackOnFlushFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows では chmod によるフラッシュ失敗シミュレーションは不可")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")
	s, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore: %v", err)
	}
	// 先に 1 エントリ保存してから上書き Save でロールバックをテスト
	existing := UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-existing",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := s.Save("user-rb", "route-rb", existing); err != nil {
		t.Fatalf("Save (initial): %v", err)
	}

	// ディレクトリを read-only にして flush を失敗させる
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("Chmod dir: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()

	newRec := UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-new",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	saveErr := s.Save("user-rb", "route-rb", newRec)
	_ = os.Chmod(dir, 0o755)
	if saveErr == nil {
		t.Fatal("expected error when flush fails, got nil")
	}

	// rollback: 元のエントリが復元されているはず
	got, ok := s.Lookup("user-rb", "route-rb")
	if !ok {
		t.Fatal("entry should be restored after failed Save")
	}
	if got.AccessToken != existing.AccessToken {
		t.Errorf("rollback: AccessToken got %q, want %q", got.AccessToken, existing.AccessToken)
	}
}

func TestFileUpstreamTokenStore_DeleteRollbackOnFlushFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows では chmod によるフラッシュ失敗シミュレーションは不可")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")
	s, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore: %v", err)
	}
	rec := UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at-del-rb",
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	if err := s.Save("user-drb", "route-drb", rec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatalf("Chmod dir: %v", err)
	}
	defer func() { _ = os.Chmod(dir, 0o755) }()

	delErr := s.Delete("user-drb", "route-drb")
	_ = os.Chmod(dir, 0o755)
	if delErr == nil {
		t.Fatal("expected error when flush fails, got nil")
	}

	// rollback: エントリが復元されているはず
	got, ok := s.Lookup("user-drb", "route-drb")
	if !ok {
		t.Fatal("entry should be restored after failed Delete")
	}
	if got.AccessToken != rec.AccessToken {
		t.Errorf("rollback: AccessToken got %q, want %q", got.AccessToken, rec.AccessToken)
	}
}

func TestFileUpstreamTokenStore_FileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows では POSIX ファイルパーミッションは適用されない")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_tokens.json")
	s, err := NewFileUpstreamTokenStore(path)
	if err != nil {
		t.Fatalf("NewFileUpstreamTokenStore: %v", err)
	}
	if err := s.Save("user", "route", UpstreamTokenRecord{
		Issuer:      "https://as.example.com",
		AccessToken: "at",
		ExpiresAt:   time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		t.Errorf("file permissions %o are too permissive (want 0600)", perm)
	}
}
