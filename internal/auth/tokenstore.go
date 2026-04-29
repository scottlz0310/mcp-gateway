package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// TokenStore persists validated token → identity mappings.
// Two implementations are provided: memTokenStore (default, in-process) and
// fileTokenStore (JSON file, survives container restarts).
type TokenStore interface {
	// Save records that token maps to subject and is valid until expiresAt.
	Save(token, subject string, expiresAt time.Time) error
	// Lookup returns the subject for a non-expired token, or ("", false).
	Lookup(token string) (subject string, ok bool)
	// Delete removes a single token entry immediately.
	Delete(token string) error
	// Sweep removes all expired entries. Called periodically by the Store janitor.
	Sweep() error
}

// tokenKey returns a SHA-256-based key so raw token values are never written
// to persistent storage.
func tokenKey(token string) string {
	h := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ── in-memory implementation ────────────────────────────────────────────────

type memEntry struct {
	subject   string
	expiresAt time.Time
}

type memTokenStore struct {
	mu      sync.RWMutex
	entries map[string]memEntry // key: tokenKey(rawToken)
}

// NewMemTokenStore returns an in-memory TokenStore.
// All data is lost when the process exits.
func NewMemTokenStore() TokenStore {
	return &memTokenStore{entries: make(map[string]memEntry)}
}

func (m *memTokenStore) Save(token, subject string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[tokenKey(token)] = memEntry{subject: subject, expiresAt: expiresAt}
	return nil
}

func (m *memTokenStore) Lookup(token string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(token)]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.subject, true
}

func (m *memTokenStore) Delete(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, tokenKey(token))
	return nil
}

func (m *memTokenStore) Sweep() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.entries {
		if now.After(v.expiresAt) {
			delete(m.entries, k)
		}
	}
	return nil
}

// ── file-backed implementation ───────────────────────────────────────────────

// fileEntry is the on-disk representation of a single token record.
// The map key is tokenKey(rawToken), so raw tokens never appear in the file.
type fileEntry struct {
	Subject   string    `json:"s"`
	ExpiresAt time.Time `json:"e"`
}

type fileTokenStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]fileEntry // key: tokenKey(rawToken)
}

// NewFileTokenStore returns a file-backed TokenStore that loads existing entries
// from path on startup and flushes atomically on every write.
// The file is created with mode 0600 (owner read/write only).
// If the file does not yet exist, an empty store is returned without error.
func NewFileTokenStore(path string) (TokenStore, error) {
	s := &fileTokenStore{
		path:    path,
		entries: make(map[string]fileEntry),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading token store %q: %w", path, err)
	}
	// Sweep stale entries immediately after load so the first Lookup is clean.
	_ = s.sweepLocked()
	count := len(s.entries)
	slog.Info("token store loaded", "path", path, "entries", count)
	return s, nil
}

func (f *fileTokenStore) Save(token, subject string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries[tokenKey(token)] = fileEntry{Subject: subject, ExpiresAt: expiresAt}
	return f.flush()
}

func (f *fileTokenStore) Lookup(token string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(token)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return "", false
	}
	return e.Subject, true
}

func (f *fileTokenStore) Delete(token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.entries, tokenKey(token))
	return f.flush()
}

func (f *fileTokenStore) Sweep() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if changed := f.sweepLocked(); !changed {
		return nil
	}
	return f.flush()
}

// sweepLocked removes expired entries and returns true if any were removed.
// Must be called with f.mu held for writing.
func (f *fileTokenStore) sweepLocked() bool {
	now := time.Now()
	changed := false
	for k, v := range f.entries {
		if now.After(v.ExpiresAt) {
			delete(f.entries, k)
			changed = true
		}
	}
	return changed
}

// load reads and unmarshals the store file. Must be called before the store
// is shared across goroutines (no lock needed during construction).
func (f *fileTokenStore) load() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &f.entries)
}

// flush writes entries to disk atomically via a temp file + rename.
// Must be called with f.mu held for writing.
func (f *fileTokenStore) flush() error {
	data, err := json.Marshal(f.entries)
	if err != nil {
		return fmt.Errorf("marshaling token store: %w", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing token store temp file: %w", err)
	}
	if err := os.Rename(tmp, f.path); err != nil {
		return fmt.Errorf("renaming token store: %w", err)
	}
	return nil
}
