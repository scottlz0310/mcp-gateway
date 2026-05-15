package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// TokenRecord is the cached metadata for an access token. Audiences is empty
// for legacy entries written before per-route audience metadata existed.
//
// ProviderRefreshToken and ProviderAccessExpiry are populated when the upstream
// OAuth provider issues short-lived (expiring) tokens. ProviderAccessExpiry is
// zero when the provider did not advertise an expiry hint; in that case the
// gateway does not attempt rotation for this token.
type TokenRecord struct {
	Subject              string
	Audiences            []string
	ExpiresAt            time.Time
	ProviderRefreshToken string
	ProviderAccessExpiry time.Time
}

// HasAudience reports whether the token record is scoped to audience.
func (r TokenRecord) HasAudience(audience string) bool {
	for _, aud := range r.Audiences {
		if aud == audience {
			return true
		}
	}
	return false
}

// TokenStore persists access token metadata.
// Two implementations are provided: memTokenStore (default, in-process) and
// fileTokenStore (JSON file, survives container restarts).
type TokenStore interface {
	// Save records that token maps to subject/audiences and is valid until expiresAt.
	// Re-saving an existing non-expired token merges audiences and preserves a
	// previously cached subject when subject is empty.
	Save(token, subject string, audiences []string, expiresAt time.Time) error
	// SaveProviderRefresh attaches GitHub-style provider refresh metadata to an
	// existing entry without disturbing subject/audiences/expiresAt. The entry
	// must already exist (created by Save); otherwise the call is a no-op.
	// Passing an empty providerRefreshToken clears the metadata.
	SaveProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) error
	// Lookup returns metadata for a non-expired token, or (zero, false).
	Lookup(token string) (TokenRecord, bool)
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
	subject              string
	audiences            []string
	expiresAt            time.Time
	providerRefreshToken string
	providerAccessExpiry time.Time
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

func (m *memTokenStore) Save(token, subject string, audiences []string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry := memEntry{}
	if current, ok := m.entries[key]; ok && time.Now().Before(current.expiresAt) {
		entry = current
	}
	if subject != "" {
		entry.subject = subject
	}
	entry.audiences = mergeAudiences(entry.audiences, audiences)
	entry.expiresAt = expiresAt
	m.entries[key] = entry
	return nil
}

// SaveProviderRefresh attaches provider refresh metadata to an existing entry.
// If no entry exists (or it has expired), the call is a no-op so we never
// resurrect a swept token by side effect.
func (m *memTokenStore) SaveProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	entry.providerRefreshToken = providerRefreshToken
	entry.providerAccessExpiry = providerAccessExpiry
	m.entries[key] = entry
	return nil
}

func (m *memTokenStore) Lookup(token string) (TokenRecord, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(token)]
	if !ok || time.Now().After(e.expiresAt) {
		return TokenRecord{}, false
	}
	return TokenRecord{
		Subject:              e.subject,
		Audiences:            cloneStrings(e.audiences),
		ExpiresAt:            e.expiresAt,
		ProviderRefreshToken: e.providerRefreshToken,
		ProviderAccessExpiry: e.providerAccessExpiry,
	}, true
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
//
// ProviderRefreshToken is stored as plaintext because the gateway must replay
// it to the upstream OAuth provider on rotation. The file is written with
// mode 0600, but operators should treat tokens.json as a long-lived
// credential surface: any reader can hijack a logged-in user's GitHub session
// until the refresh token is revoked (typically the OAuth App rotation
// window — months). Snapshot, backup, and access-control implications are
// covered in docs/configuration.md under "Token Persistence".
type fileEntry struct {
	Subject              string    `json:"s"`
	Audiences            []string  `json:"aud,omitempty"`
	ExpiresAt            time.Time `json:"e"`
	ProviderRefreshToken string    `json:"prt,omitempty"`
	ProviderAccessExpiry time.Time `json:"pae,omitempty"`
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
	if err := s.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading token store %q: %w", path, err)
		}
		// File doesn't exist yet — verify the parent directory exists, is a
		// directory, and is writable so later Save calls don't fail due to a
		// startup-time misconfiguration.
		dir := filepath.Dir(path)
		info, statErr := os.Stat(dir)
		if statErr != nil {
			return nil, fmt.Errorf("token store parent directory inaccessible %q: %w", dir, statErr)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("token store parent path is not a directory %q", dir)
		}
		f, createErr := os.CreateTemp(dir, ".tokenstore-writecheck-*")
		if createErr != nil {
			return nil, fmt.Errorf("token store parent directory not writable %q: %w", dir, createErr)
		}
		name := f.Name()
		if closeErr := f.Close(); closeErr != nil {
			_ = os.Remove(name)
			return nil, fmt.Errorf("closing token store parent directory probe file in %q: %w", dir, closeErr)
		}
		if removeErr := os.Remove(name); removeErr != nil {
			return nil, fmt.Errorf("removing token store parent directory probe file %q: %w", name, removeErr)
		}
	}
	// Sweep stale entries immediately after load; flush to disk when any were removed.
	// Hold the write lock to satisfy flush()'s locking contract even though the store
	// is not yet shared across goroutines.
	s.mu.Lock()
	if changed := s.sweepLocked(); changed {
		if err := s.flush(); err != nil {
			count := len(s.entries)
			s.mu.Unlock()
			slog.Warn("token store startup sweep flush failed", "path", path, "err", err)
			// Non-fatal: the store is still usable; stale entries will be removed
			// by the next periodic Sweep.
			slog.Info("token store loaded", "path", path, "entries", count)
			return s, nil
		}
	}
	count := len(s.entries)
	s.mu.Unlock()
	// Best-effort: enforce owner-only permissions on an existing file so the
	// security property holds even when the file was pre-created with looser perms.
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		slog.Warn("token store chmod failed", "path", path, "err", err)
	}
	slog.Info("token store loaded", "path", path, "entries", count)
	return s, nil
}

func (f *fileTokenStore) Save(token, subject string, audiences []string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry := fileEntry{}
	if current, ok := f.entries[key]; ok && time.Now().Before(current.ExpiresAt) {
		entry = current
	}
	if subject != "" {
		entry.Subject = subject
	}
	entry.Audiences = mergeAudiences(entry.Audiences, audiences)
	entry.ExpiresAt = expiresAt
	f.entries[key] = entry
	return f.flush()
}

// SaveProviderRefresh updates the provider refresh metadata on an existing
// entry. If the entry is missing or expired the call is a no-op and the file
// is NOT rewritten. Failure to flush rolls back the in-memory mutation so
// disk and memory remain consistent.
func (f *fileTokenStore) SaveProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.ProviderRefreshToken = providerRefreshToken
	entry.ProviderAccessExpiry = providerAccessExpiry
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
}

func (f *fileTokenStore) Lookup(token string) (TokenRecord, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(token)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return TokenRecord{}, false
	}
	return TokenRecord{
		Subject:              e.Subject,
		Audiences:            cloneStrings(e.Audiences),
		ExpiresAt:            e.ExpiresAt,
		ProviderRefreshToken: e.ProviderRefreshToken,
		ProviderAccessExpiry: e.ProviderAccessExpiry,
	}, true
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
	if len(data) == 0 {
		return nil // empty or pre-created file — treat as empty store
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
	if err := os.Rename(tmp, f.path); err == nil {
		return nil
	}
	// On some Windows configurations rename fails when the destination exists.
	// Use a backup-based strategy: rename the existing store aside first, promote
	// the temp file, then remove the backup. On any failure we can restore.
	backup := f.path + ".bak"
	_ = os.Remove(backup)

	hadOriginal := false
	if err2 := os.Rename(f.path, backup); err2 == nil {
		hadOriginal = true
	} else if !os.IsNotExist(err2) {
		_ = os.Remove(tmp)
		return fmt.Errorf("backing up token store: %w", err2)
	}

	if err2 := os.Rename(tmp, f.path); err2 != nil {
		if hadOriginal {
			if restoreErr := os.Rename(backup, f.path); restoreErr != nil {
				return fmt.Errorf("renaming token store: %w (restore failed: %v)", err2, restoreErr)
			}
		}
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming token store: %w", err2)
	}
	if hadOriginal {
		_ = os.Remove(backup)
	}
	return nil
}

// ── RefreshTokenStore ────────────────────────────────────────────────────────

// RefreshTokenStore persists gateway-issued refresh token → access token mappings.
// Two implementations: memRefreshTokenStore (default) and fileRefreshTokenStore (JSON file).
type RefreshTokenStore interface {
	// Save records that refreshToken maps to accessToken/audience and is valid until expiresAt.
	Save(refreshToken, accessToken, audience string, expiresAt time.Time) error
	// Lookup returns the access token, audience, and expiry for a non-expired refresh token, or ("", "", zero, false).
	// expiresAt is returned so that RestoreRefreshToken can re-save with the original expiry on rotation failure.
	Lookup(refreshToken string) (accessToken, audience string, expiresAt time.Time, ok bool)
	// Delete removes a single refresh token entry immediately.
	Delete(refreshToken string) error
	// Sweep removes all expired entries. Called periodically by the Store janitor.
	Sweep() error
}

// ── in-memory RefreshTokenStore ───────────────────────────────────────────────

type memRTEntry struct {
	accessToken string
	audience    string
	expiresAt   time.Time
}

type memRefreshTokenStore struct {
	mu      sync.RWMutex
	entries map[string]memRTEntry // key: tokenKey(rawRefreshToken)
}

// NewMemRefreshTokenStore returns an in-memory RefreshTokenStore.
// All data is lost when the process exits.
func NewMemRefreshTokenStore() RefreshTokenStore {
	return &memRefreshTokenStore{entries: make(map[string]memRTEntry)}
}

func (m *memRefreshTokenStore) Save(refreshToken, accessToken, audience string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries[tokenKey(refreshToken)] = memRTEntry{accessToken: accessToken, audience: audience, expiresAt: expiresAt}
	return nil
}

func (m *memRefreshTokenStore) Lookup(refreshToken string) (string, string, time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.expiresAt) {
		return "", "", time.Time{}, false
	}
	return e.accessToken, e.audience, e.expiresAt, true
}

func (m *memRefreshTokenStore) Delete(refreshToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, tokenKey(refreshToken))
	return nil
}

func (m *memRefreshTokenStore) Sweep() error {
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

// ── file-backed RefreshTokenStore ─────────────────────────────────────────────

// fileRTEntry is the on-disk representation of a single refresh token record.
// The map key is tokenKey(rawRefreshToken), so raw refresh token values never
// appear in the file. The plaintext access token is stored as the value because
// the gateway must re-present it to the upstream provider on token refresh.
type fileRTEntry struct {
	AccessToken string    `json:"a"`
	Audience    string    `json:"aud,omitempty"`
	ExpiresAt   time.Time `json:"e"`
}

type fileRefreshTokenStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]fileRTEntry // key: tokenKey(rawRefreshToken)
}

// NewFileRefreshTokenStore returns a file-backed RefreshTokenStore that loads
// existing entries from path on startup and flushes atomically on every write.
// The file is created with mode 0600 (owner read/write only).
// If the file does not yet exist, an empty store is returned without error.
func NewFileRefreshTokenStore(path string) (RefreshTokenStore, error) {
	s := &fileRefreshTokenStore{
		path:    path,
		entries: make(map[string]fileRTEntry),
	}
	if err := s.load(); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("loading refresh token store %q: %w", path, err)
		}
		dir := filepath.Dir(path)
		info, statErr := os.Stat(dir)
		if statErr != nil {
			return nil, fmt.Errorf("refresh token store parent directory inaccessible %q: %w", dir, statErr)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("refresh token store parent path is not a directory %q", dir)
		}
		f, createErr := os.CreateTemp(dir, ".reftokenstore-writecheck-*")
		if createErr != nil {
			return nil, fmt.Errorf("refresh token store parent directory not writable %q: %w", dir, createErr)
		}
		name := f.Name()
		if closeErr := f.Close(); closeErr != nil {
			_ = os.Remove(name)
			return nil, fmt.Errorf("closing refresh token store probe file in %q: %w", dir, closeErr)
		}
		if removeErr := os.Remove(name); removeErr != nil {
			return nil, fmt.Errorf("removing refresh token store probe file %q: %w", name, removeErr)
		}
	}
	s.mu.Lock()
	if changed := s.sweepLocked(); changed {
		if err := s.flush(); err != nil {
			count := len(s.entries)
			s.mu.Unlock()
			slog.Warn("refresh token store startup sweep flush failed", "path", path, "err", err)
			slog.Info("refresh token store loaded", "path", path, "entries", count)
			return s, nil
		}
	}
	count := len(s.entries)
	s.mu.Unlock()
	if err := os.Chmod(path, 0o600); err != nil && !os.IsNotExist(err) {
		slog.Warn("refresh token store chmod failed", "path", path, "err", err)
	}
	slog.Info("refresh token store loaded", "path", path, "entries", count)
	return s, nil
}

func (f *fileRefreshTokenStore) Save(refreshToken, accessToken, audience string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(refreshToken)
	prev, hasPrev := f.entries[key]
	f.entries[key] = fileRTEntry{AccessToken: accessToken, Audience: audience, ExpiresAt: expiresAt}
	if err := f.flush(); err != nil {
		if hasPrev {
			f.entries[key] = prev
		} else {
			delete(f.entries, key)
		}
		return err
	}
	return nil
}

func (f *fileRefreshTokenStore) Lookup(refreshToken string) (string, string, time.Time, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return "", "", time.Time{}, false
	}
	return e.AccessToken, e.Audience, e.ExpiresAt, true
}

func (f *fileRefreshTokenStore) Delete(refreshToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(refreshToken)
	saved, existed := f.entries[key]
	if !existed {
		return nil
	}
	delete(f.entries, key)
	if err := f.flush(); err != nil {
		f.entries[key] = saved // restore in-memory on flush failure
		return err
	}
	return nil
}

func (f *fileRefreshTokenStore) Sweep() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if changed := f.sweepLocked(); !changed {
		return nil
	}
	return f.flush()
}

func (f *fileRefreshTokenStore) sweepLocked() bool {
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

func (f *fileRefreshTokenStore) load() error {
	data, err := os.ReadFile(f.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &f.entries)
}

func (f *fileRefreshTokenStore) flush() error {
	data, err := json.Marshal(f.entries)
	if err != nil {
		return fmt.Errorf("marshaling refresh token store: %w", err)
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return fmt.Errorf("writing refresh token store temp file: %w", err)
	}
	if err := os.Rename(tmp, f.path); err == nil {
		return nil
	}
	// Windows fallback: backup existing file, promote temp, then remove backup.
	backup := f.path + ".bak"
	_ = os.Remove(backup)

	hadOriginal := false
	if err2 := os.Rename(f.path, backup); err2 == nil {
		hadOriginal = true
	} else if !os.IsNotExist(err2) {
		_ = os.Remove(tmp)
		return fmt.Errorf("backing up refresh token store: %w", err2)
	}

	if err2 := os.Rename(tmp, f.path); err2 != nil {
		if hadOriginal {
			if restoreErr := os.Rename(backup, f.path); restoreErr != nil {
				return fmt.Errorf("renaming refresh token store: %w (restore failed: %v)", err2, restoreErr)
			}
		}
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming refresh token store: %w", err2)
	}
	if hadOriginal {
		_ = os.Remove(backup)
	}
	return nil
}

func mergeAudiences(existing, additions []string) []string {
	out := cloneStrings(existing)
	seen := make(map[string]struct{}, len(out)+len(additions))
	for _, aud := range out {
		seen[aud] = struct{}{}
	}
	for _, aud := range additions {
		aud = strings.TrimRight(strings.TrimSpace(aud), "/")
		if aud == "" {
			continue
		}
		if _, ok := seen[aud]; ok {
			continue
		}
		seen[aud] = struct{}{}
		out = append(out, aud)
	}
	return out
}

func cloneStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, len(in))
	copy(out, in)
	return out
}
