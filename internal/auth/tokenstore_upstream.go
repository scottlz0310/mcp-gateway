package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// UpstreamTokenRecord is the in-memory representation of an upstream OAuth
// token for a specific (subject, route) pair.
// Subject and RouteName are not persisted to disk; they are recovered from the
// map key (sha256 hash) at runtime via the caller-supplied lookup key.
type UpstreamTokenRecord struct {
	Subject      string    // in-memory only; not written to disk
	RouteName    string    // in-memory only; not written to disk
	Grant        string    // "authorization_code" or "client_credentials"; empty = "authorization_code"
	Issuer       string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time // zero value = expiry unknown / treat as permanent
	Scope        string
}

// UpstreamTokenStore persists upstream OAuth access_token / refresh_token pairs
// keyed by (subject, routeName). Implementations must be safe for concurrent use.
type UpstreamTokenStore interface {
	// Save writes or replaces the upstream token record for (subject, routeName).
	Save(subject, routeName string, record UpstreamTokenRecord) error
	// Lookup returns the token record for (subject, routeName).
	// Returns false when no record exists or the record has expired.
	Lookup(subject, routeName string) (UpstreamTokenRecord, bool)
	// LookupForRefresh returns the stored record regardless of access token expiry,
	// so that a valid refresh_token can be retrieved even when the access token is
	// already expired. Returns false only when no record exists at all.
	LookupForRefresh(subject, routeName string) (UpstreamTokenRecord, bool)
	// Delete removes the token record for (subject, routeName).
	Delete(subject, routeName string) error
	// Sweep removes all expired entries.
	Sweep() error
}

// upstreamTokenKey returns the map key for (subject, routeName).
// Raw identity is not stored; only the hash appears in the file.
func upstreamTokenKey(subject, routeName string) string {
	h := sha256.Sum256([]byte(subject + "\x00" + routeName))
	return hex.EncodeToString(h[:])
}

// upstreamTokenFileEntry is the on-disk representation of a single upstream
// token record. Subject and RouteName are intentionally absent from the JSON
// so that raw identity information is never written to disk.
type upstreamTokenFileEntry struct {
	Grant        string     `json:"grant,omitempty"`
	Issuer       string     `json:"issuer"`
	AccessToken  string     `json:"access_token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
	Scope        string     `json:"scope,omitempty"`
}

func (e upstreamTokenFileEntry) expired() bool {
	return e.ExpiresAt != nil && time.Now().After(*e.ExpiresAt)
}

// ── in-memory implementation ─────────────────────────────────────────────────

type memUpstreamTokenStore struct {
	mu      sync.RWMutex
	entries map[string]UpstreamTokenRecord // key: upstreamTokenKey
}

// NewMemUpstreamTokenStore returns an in-memory UpstreamTokenStore suitable
// for testing or configurations without a persistent state directory.
func NewMemUpstreamTokenStore() UpstreamTokenStore {
	return &memUpstreamTokenStore{entries: make(map[string]UpstreamTokenRecord)}
}

func (m *memUpstreamTokenStore) Save(subject, routeName string, record UpstreamTokenRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	record.Subject = subject
	record.RouteName = routeName
	m.entries[upstreamTokenKey(subject, routeName)] = record
	return nil
}

func (m *memUpstreamTokenStore) Lookup(subject, routeName string) (UpstreamTokenRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.entries[upstreamTokenKey(subject, routeName)]
	if !ok {
		return UpstreamTokenRecord{}, false
	}
	if !rec.ExpiresAt.IsZero() && time.Now().After(rec.ExpiresAt) {
		return UpstreamTokenRecord{}, false
	}
	return rec, true
}

func (m *memUpstreamTokenStore) LookupForRefresh(subject, routeName string) (UpstreamTokenRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.entries[upstreamTokenKey(subject, routeName)]
	if !ok {
		return UpstreamTokenRecord{}, false
	}
	return rec, true
}

func (m *memUpstreamTokenStore) Delete(subject, routeName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, upstreamTokenKey(subject, routeName))
	return nil
}

func (m *memUpstreamTokenStore) Sweep() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.entries {
		// Keep records that have a refresh_token: the access token may be expired
		// but RefreshAfter401 still needs the refresh_token to obtain a new one.
		// Records without a refresh_token are swept when the access token expires.
		if !v.ExpiresAt.IsZero() && now.After(v.ExpiresAt) && v.RefreshToken == "" {
			delete(m.entries, k)
		}
	}
	return nil
}

// ── file-backed implementation ────────────────────────────────────────────────

type fileUpstreamTokenStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]upstreamTokenFileEntry // key: upstreamTokenKey
}

// NewFileUpstreamTokenStore returns a file-backed UpstreamTokenStore that
// loads existing entries from path on startup, sweeps expired entries, and
// flushes atomically on every write. The file is written with mode 0600.
// If path does not exist the store starts empty; the parent directory must
// exist and be writable.
func NewFileUpstreamTokenStore(path string) (UpstreamTokenStore, error) {
	s := &fileUpstreamTokenStore{
		path:    path,
		entries: make(map[string]upstreamTokenFileEntry),
	}
	if err := s.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading upstream token store %q: %w", path, err)
		}
		dir := filepath.Dir(path)
		info, statErr := os.Stat(dir)
		if statErr != nil {
			return nil, fmt.Errorf("upstream token store parent directory inaccessible %q: %w", dir, statErr)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("upstream token store parent path is not a directory %q", dir)
		}
		f, createErr := os.CreateTemp(dir, ".upstreamtokens-writecheck-*")
		if createErr != nil {
			return nil, fmt.Errorf("upstream token store parent directory not writable %q: %w", dir, createErr)
		}
		name := f.Name()
		if closeErr := f.Close(); closeErr != nil {
			_ = os.Remove(name)
			return nil, fmt.Errorf("closing upstream token store probe file in %q: %w", dir, closeErr)
		}
		if removeErr := os.Remove(name); removeErr != nil {
			return nil, fmt.Errorf("removing upstream token store probe file %q: %w", name, removeErr)
		}
	}
	s.mu.Lock()
	if changed := s.sweepLocked(); changed {
		if err := s.flush(); err != nil {
			count := len(s.entries)
			s.mu.Unlock()
			slog.Warn("upstream token store startup sweep flush failed", "path", path, "err", err)
			slog.Info("upstream token store loaded", "path", path, "entries", count)
			return s, nil
		}
	}
	count := len(s.entries)
	s.mu.Unlock()
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		slog.Warn("upstream token store chmod failed", "path", path, "err", err)
	}
	slog.Info("upstream token store loaded", "path", path, "entries", count)
	return s, nil
}

func (s *fileUpstreamTokenStore) Save(subject, routeName string, record UpstreamTokenRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := upstreamTokenKey(subject, routeName)
	prev, hadPrev := s.entries[key]
	var expiresAt *time.Time
	if !record.ExpiresAt.IsZero() {
		t := record.ExpiresAt
		expiresAt = &t
	}
	s.entries[key] = upstreamTokenFileEntry{
		Grant:        record.Grant,
		Issuer:       record.Issuer,
		AccessToken:  record.AccessToken,
		RefreshToken: record.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        record.Scope,
	}
	if err := s.flush(); err != nil {
		if hadPrev {
			s.entries[key] = prev
		} else {
			delete(s.entries, key)
		}
		return err
	}
	return nil
}

func (s *fileUpstreamTokenStore) Lookup(subject, routeName string) (UpstreamTokenRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[upstreamTokenKey(subject, routeName)]
	if !ok || entry.expired() {
		return UpstreamTokenRecord{}, false
	}
	var expiresAt time.Time
	if entry.ExpiresAt != nil {
		expiresAt = *entry.ExpiresAt
	}
	return UpstreamTokenRecord{
		Subject:      subject,
		RouteName:    routeName,
		Grant:        entry.Grant,
		Issuer:       entry.Issuer,
		AccessToken:  entry.AccessToken,
		RefreshToken: entry.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        entry.Scope,
	}, true
}

func (s *fileUpstreamTokenStore) LookupForRefresh(subject, routeName string) (UpstreamTokenRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.entries[upstreamTokenKey(subject, routeName)]
	if !ok {
		return UpstreamTokenRecord{}, false
	}
	var expiresAt time.Time
	if entry.ExpiresAt != nil {
		expiresAt = *entry.ExpiresAt
	}
	return UpstreamTokenRecord{
		Subject:      subject,
		RouteName:    routeName,
		Grant:        entry.Grant,
		Issuer:       entry.Issuer,
		AccessToken:  entry.AccessToken,
		RefreshToken: entry.RefreshToken,
		ExpiresAt:    expiresAt,
		Scope:        entry.Scope,
	}, true
}

func (s *fileUpstreamTokenStore) Delete(subject, routeName string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := upstreamTokenKey(subject, routeName)
	prev, hadPrev := s.entries[key]
	delete(s.entries, key)
	if err := s.flush(); err != nil {
		if hadPrev {
			s.entries[key] = prev
		}
		return err
	}
	return nil
}

func (s *fileUpstreamTokenStore) Sweep() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if changed := s.sweepLocked(); !changed {
		return nil
	}
	return s.flush()
}

func (s *fileUpstreamTokenStore) sweepLocked() bool {
	changed := false
	for k, v := range s.entries {
		// Keep records that have a refresh_token even after the access token expires.
		// RefreshAfter401 needs the refresh_token to renew the access token.
		if v.expired() && v.RefreshToken == "" {
			delete(s.entries, k)
			changed = true
		}
	}
	return changed
}

func (s *fileUpstreamTokenStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &s.entries)
}

// flush writes entries to disk atomically via temp file + rename.
// Must be called with s.mu held for writing.
func (s *fileUpstreamTokenStore) flush() error {
	data, err := json.Marshal(s.entries)
	if err != nil {
		return fmt.Errorf("marshaling upstream token store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing upstream token store temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err == nil {
		return nil
	}
	backup := s.path + ".bak"
	_ = os.Remove(backup)
	hadOriginal := false
	if err2 := os.Rename(s.path, backup); err2 == nil {
		hadOriginal = true
	} else if !os.IsNotExist(err2) {
		_ = os.Remove(tmp)
		return fmt.Errorf("backing up upstream token store: %w", err2)
	}
	if err2 := os.Rename(tmp, s.path); err2 != nil {
		if hadOriginal {
			if restoreErr := os.Rename(backup, s.path); restoreErr != nil {
				return fmt.Errorf("renaming upstream token store: %w (restore failed: %v)", err2, restoreErr)
			}
		}
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming upstream token store: %w", err2)
	}
	if hadOriginal {
		_ = os.Remove(backup)
	}
	return nil
}
