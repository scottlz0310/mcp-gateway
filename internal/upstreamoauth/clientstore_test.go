package upstreamoauth

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func newTestStore(t *testing.T) (ClientStore, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_clients.json")
	s, err := NewFileClientStore(path)
	if err != nil {
		t.Fatalf("NewFileClientStore: %v", err)
	}
	return s, path
}

func sampleRecord(routeName string) ClientRecord {
	return ClientRecord{
		RouteName:             routeName,
		Issuer:                "https://as.example.com",
		AuthorizationEndpoint: "https://as.example.com/authorize",
		TokenEndpoint:         "https://as.example.com/token",
		RegistrationEndpoint:  "https://as.example.com/register",
		ClientID:              "cid-" + routeName,
		ClientSecret:          "secret-" + routeName,
		RegisteredAt:          time.Now().UTC().Truncate(time.Second),
	}
}

func TestFileClientStore_SaveAndLoad(t *testing.T) {
	s, _ := newTestStore(t)
	rec := sampleRecord("route-a")

	if err := s.Save(rec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, ok := s.Load("route-a")
	if !ok {
		t.Fatal("Load: expected record, got not-found")
	}
	if got.ClientID != rec.ClientID {
		t.Errorf("ClientID: got %q, want %q", got.ClientID, rec.ClientID)
	}
}

func TestFileClientStore_LoadAbsent(t *testing.T) {
	s, _ := newTestStore(t)
	_, ok := s.Load("nonexistent")
	if ok {
		t.Fatal("Load: expected not-found for absent key, got found")
	}
}

func TestFileClientStore_Persistence(t *testing.T) {
	_, path := newTestStore(t)
	rec := sampleRecord("route-b")

	s1, err := NewFileClientStore(path)
	if err != nil {
		t.Fatalf("NewFileClientStore (first): %v", err)
	}
	if err := s1.Save(rec); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// 別インスタンスで同じファイルを開き直す
	s2, err := NewFileClientStore(path)
	if err != nil {
		t.Fatalf("NewFileClientStore (second): %v", err)
	}
	got, ok := s2.Load("route-b")
	if !ok {
		t.Fatal("Load (second instance): expected record, got not-found")
	}
	if got.ClientID != rec.ClientID {
		t.Errorf("ClientID: got %q, want %q", got.ClientID, rec.ClientID)
	}
}

func TestFileClientStore_EmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "upstream_clients.json")
	// 空ファイルを事前作成
	if err := os.WriteFile(path, []byte{}, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	s, err := NewFileClientStore(path)
	if err != nil {
		t.Fatalf("NewFileClientStore with empty file: %v", err)
	}
	if all := s.All(); len(all) != 0 {
		t.Errorf("expected 0 records from empty file, got %d", len(all))
	}
}

func TestFileClientStore_All(t *testing.T) {
	s, _ := newTestStore(t)
	routes := []string{"route-x", "route-y", "route-z"}
	for _, r := range routes {
		if err := s.Save(sampleRecord(r)); err != nil {
			t.Fatalf("Save(%q): %v", r, err)
		}
	}

	all := s.All()
	if len(all) != len(routes) {
		t.Errorf("All(): got %d records, want %d", len(all), len(routes))
	}
}

func TestFileClientStore_SaveUpdatesExisting(t *testing.T) {
	s, _ := newTestStore(t)
	rec := sampleRecord("route-update")
	if err := s.Save(rec); err != nil {
		t.Fatalf("Save (initial): %v", err)
	}

	rec.ClientID = "new-client-id"
	if err := s.Save(rec); err != nil {
		t.Fatalf("Save (update): %v", err)
	}

	got, ok := s.Load("route-update")
	if !ok {
		t.Fatal("Load: expected record after update")
	}
	if got.ClientID != "new-client-id" {
		t.Errorf("ClientID after update: got %q, want %q", got.ClientID, "new-client-id")
	}
}

func TestFileClientStore_NonExistentFileIsOK(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "does_not_exist.json")
	s, err := NewFileClientStore(path)
	if err != nil {
		t.Fatalf("NewFileClientStore with non-existent file: %v", err)
	}
	if all := s.All(); len(all) != 0 {
		t.Errorf("expected 0 records, got %d", len(all))
	}
}

func TestFileClientStore_ParentDirNotExist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nonexistent-dir", "upstream_clients.json")
	_, err := NewFileClientStore(path)
	if err == nil {
		t.Fatal("expected error when parent directory does not exist, got nil")
	}
}

func TestFileClientStore_FileMode(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows では POSIX ファイルパーミッションは適用されない")
	}
	s, path := newTestStore(t)
	if err := s.Save(sampleRecord("route-mode")); err != nil {
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
