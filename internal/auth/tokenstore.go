package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
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
// ProviderAccessToken is the upstream OAuth provider's access token (e.g. a
// GitHub token) associated with this entry. In builtin mode the token map key
// is a gateway-issued JWT, not the provider token itself, so this field is the
// only place the provider token is recoverable from — used by
// EnsureFreshAccessTokenForSubject (Phase B delegated access). Empty for
// non-builtin mode, where the map key IS the provider access token already.
//
// ProviderRefreshToken and ProviderAccessExpiry are populated when the upstream
// OAuth provider issues short-lived (expiring) tokens. ProviderAccessExpiry is
// zero when the provider did not advertise an expiry hint; in that case the
// gateway does not attempt rotation for this token.
//
// RotationPermanentlyFailed is set when the provider has permanently rejected
// rotation for this token (e.g., bad or revoked refresh token). Once set it
// survives gateway restarts when using a file-backed store so that
// ValidateToken never re-seeds the subject index with a dead bearer.
//
// Nonce is the OIDC nonce from the original authorization request (OIDC Core
// §3.1.3.7). It is propagated to id_token on refresh (OIDC Core §12.2) so
// that the nonce binding survives token rotation. Empty when no nonce was
// requested.
//
// Jti is the JWT ID claim of the gateway-issued access token (builtin mode
// only). It is cached alongside the token record so that a cache-hit
// ValidateToken call can check the entry against the revocation denylist
// (RevokeJTI/IsJTIRevoked) without re-parsing the raw token. Empty for
// non-builtin mode and for JWTs issued before this field existed.
type TokenRecord struct {
	Subject                   string
	Audiences                 []string
	ExpiresAt                 time.Time
	ProviderAccessToken       string
	ProviderRefreshToken      string
	ProviderAccessExpiry      time.Time
	RotationPermanentlyFailed bool
	Nonce                     string
	Jti                       string
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
	// SaveProviderAccessToken attaches the upstream provider's access token
	// (e.g. a GitHub token) to an existing entry, without disturbing any other
	// field. The entry must already exist (created by Save); otherwise the
	// call is a no-op. Used by builtin mode, where the map key is a
	// gateway-issued JWT rather than the provider token itself.
	SaveProviderAccessToken(token, providerAccessToken string) error
	// Lookup returns metadata for a non-expired token, or (zero, false).
	Lookup(token string) (TokenRecord, bool)
	// SaveNonce attaches the OIDC nonce to an existing entry so it can be
	// forwarded in id_token on refresh (OIDC Core §12.2). The entry must
	// already exist; if absent or expired the call is a no-op. An empty
	// nonce clears any previously stored value.
	SaveNonce(token, nonce string) error
	// SaveJti attaches the JWT ID claim (builtin mode) to an existing entry so
	// cache-hit ValidateToken calls can check it against the revocation
	// denylist. The entry must already exist; if absent or expired the call
	// is a no-op.
	SaveJti(token, jti string) error
	// MarkRotationFailed marks token as having a permanent rotation failure.
	// The entry must already exist; if it is absent or expired the call is a
	// no-op. For file-backed stores the flag is flushed to disk immediately so
	// it survives a gateway restart.
	MarkRotationFailed(token string) error
	// Delete removes a single token entry immediately.
	Delete(token string) error
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
	subject                   string
	audiences                 []string
	expiresAt                 time.Time
	providerAccessToken       string
	providerRefreshToken      string
	providerAccessExpiry      time.Time
	rotationPermanentlyFailed bool
	nonce                     string
	jti                       string
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

// SaveProviderAccessToken attaches the provider access token to an existing
// entry. If no entry exists (or it has expired), the call is a no-op so we
// never resurrect a swept token by side effect.
func (m *memTokenStore) SaveProviderAccessToken(token, providerAccessToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	entry.providerAccessToken = providerAccessToken
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
		Subject:                   e.subject,
		Audiences:                 cloneStrings(e.audiences),
		ExpiresAt:                 e.expiresAt,
		ProviderAccessToken:       e.providerAccessToken,
		ProviderRefreshToken:      e.providerRefreshToken,
		ProviderAccessExpiry:      e.providerAccessExpiry,
		RotationPermanentlyFailed: e.rotationPermanentlyFailed,
		Nonce:                     e.nonce,
		Jti:                       e.jti,
	}, true
}

func (m *memTokenStore) SaveNonce(token, nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	entry.nonce = nonce
	m.entries[key] = entry
	return nil
}

func (m *memTokenStore) SaveJti(token, jti string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	entry.jti = jti
	m.entries[key] = entry
	return nil
}

func (m *memTokenStore) MarkRotationFailed(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(token)
	entry, ok := m.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	entry.rotationPermanentlyFailed = true
	m.entries[key] = entry
	return nil
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
// until the refresh token is revoked (typically the GitHub App rotation
// window — months). Snapshot, backup, and access-control implications are
// covered in docs/configuration.md under "Token Persistence".
type fileEntry struct {
	Subject              string    `json:"s"`
	Audiences            []string  `json:"aud,omitempty"`
	ExpiresAt            time.Time `json:"e"`
	ProviderAccessToken  string    `json:"pat,omitempty"`
	ProviderRefreshToken string    `json:"prt,omitempty"`
	ProviderAccessExpiry time.Time `json:"pae,omitempty"`
	RotationFailed       bool      `json:"rf,omitempty"`
	Nonce                string    `json:"n,omitempty"`
	Jti                  string    `json:"jti,omitempty"`
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

// SaveProviderAccessToken updates the provider access token on an existing
// entry. If the entry is missing or expired the call is a no-op and the file
// is NOT rewritten. Failure to flush rolls back the in-memory mutation so
// disk and memory remain consistent.
func (f *fileTokenStore) SaveProviderAccessToken(token, providerAccessToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.ProviderAccessToken = providerAccessToken
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
		Subject:                   e.Subject,
		Audiences:                 cloneStrings(e.Audiences),
		ExpiresAt:                 e.ExpiresAt,
		ProviderAccessToken:       e.ProviderAccessToken,
		ProviderRefreshToken:      e.ProviderRefreshToken,
		ProviderAccessExpiry:      e.ProviderAccessExpiry,
		RotationPermanentlyFailed: e.RotationFailed,
		Nonce:                     e.Nonce,
		Jti:                       e.Jti,
	}, true
}

func (f *fileTokenStore) SaveNonce(token, nonce string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.Nonce = nonce
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
}

func (f *fileTokenStore) SaveJti(token, jti string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.Jti = jti
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
}

func (f *fileTokenStore) MarkRotationFailed(token string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(token)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.RotationFailed = true
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
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

// ErrRefreshTokenFamilyRevoked is returned by Save when familyID has been
// tombstoned by a prior RevokeFamily call. This closes a TOCTOU race between
// POST /revoke (which revokes a family) and a concurrently in-flight
// tokenRefresh rotation for the same family: without the tombstone, a
// rotation that reads its old row before RevokeFamily's UPDATE but writes
// its new row after would create a fresh, non-revoked entry that survives
// the revocation. familyID == "" is never tombstoned (Save always succeeds
// for it), matching RevokeFamily's existing no-op for an empty familyID.
var ErrRefreshTokenFamilyRevoked = errors.New("refresh token family has been revoked")

// RefreshTokenStore persists gateway-issued refresh token → access token mappings.
// Two implementations: memRefreshTokenStore (default) and fileRefreshTokenStore (JSON file).
//
// Token family tracking (RFC 6819 §5.2.2.3): every refresh token belongs to a
// family identified by a familyID generated at authorization-code issuance and
// inherited across rotations. When a revoked token is presented again (reuse
// attack), RevokeFamily invalidates the entire lineage.
type RefreshTokenStore interface {
	// Save records that refreshToken maps to accessToken/audience/familyID and
	// is valid until expiresAt. Returns ErrRefreshTokenFamilyRevoked (without
	// writing) when familyID is non-empty and has been tombstoned by a prior
	// RevokeFamily call — see ErrRefreshTokenFamilyRevoked.
	Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error
	// Lookup returns the access token, audience, familyID, and expiry for an active (non-revoked,
	// non-expired) refresh token. Returns false when the token is unknown, expired, or revoked.
	// expiresAt is returned so that RestoreRefreshToken can re-save with the original expiry on rotation failure.
	Lookup(refreshToken string) (accessToken, audience, familyID string, expiresAt time.Time, ok bool)
	// LookupAny is like Lookup but also returns revoked entries that have not yet expired.
	// Used for reuse detection: a revoked-but-present entry indicates a replay attack.
	LookupAny(refreshToken string) (accessToken, audience, familyID string, expiresAt time.Time, revoked, ok bool)
	// LookupActiveByFamily returns the access token of the current (non-revoked,
	// non-expired) refresh-token row for familyID, or ("", false) when none
	// exists. Used by POST /revoke to find the access token actually in use
	// today even when the presented refresh token is a stale, already-rotated
	// predecessor whose own accessToken field points at an earlier JWT.
	LookupActiveByFamily(familyID string) (accessToken string, ok bool)
	// Revoke marks a single refresh token as revoked without deleting it.
	// The revoked entry is retained until it expires so that reuse detection
	// (via LookupAny) can identify replay attacks within the expiry window.
	Revoke(refreshToken string) error
	// RevokeFamily marks all non-revoked tokens belonging to familyID as
	// revoked AND tombstones familyID (permanently; see
	// ErrRefreshTokenFamilyRevoked) so a concurrently in-flight Save for the
	// same familyID is rejected rather than resurrecting the family. Used on
	// reuse detection to invalidate the entire token lineage.
	RevokeFamily(familyID string) error
	// Delete removes a single refresh token entry immediately.
	Delete(refreshToken string) error
	// SaveNonce attaches the OIDC nonce to an existing refresh-token entry so it
	// can be forwarded in id_token on refresh (OIDC Core §12.2). No-op when
	// entry is absent or expired. An empty nonce clears any previously stored value.
	SaveNonce(refreshToken, nonce string) error
	// LookupNonce returns the OIDC nonce stored for refreshToken, or "" when
	// absent, expired, or nonce was never set. Returns the nonce even for
	// soft-revoked (already-rotated) entries so it can be read after ReserveRefreshToken.
	LookupNonce(refreshToken string) string
	// SaveProviderAccessToken attaches the upstream provider's access token
	// (e.g. a GitHub token) to an existing refresh-token entry, so it survives
	// past the access token's TTL. The access-token TokenStore entry (builtin
	// mode: a gateway JWT) can be swept before its refresh token expires
	// (refresh tokens carry a 30-day grace period beyond the access token
	// TTL), so this is the only reliable place to recover the provider token
	// when tokenRefresh runs during that gap. No-op when entry is absent or
	// expired.
	SaveProviderAccessToken(refreshToken, providerAccessToken string) error
	// LookupProviderAccessToken returns the provider access token stored for
	// refreshToken, or "" when absent, expired, or never set. Returns the
	// value even for soft-revoked (already-rotated) entries so it can be read
	// after ReserveRefreshToken, mirroring LookupNonce.
	LookupProviderAccessToken(refreshToken string) string
	// RevokeJTI adds the JWT ID (jti claim) of a gateway-issued access token
	// (builtin mode) to the revocation denylist until expiresAt, which should
	// be the token's own exp claim so the entry is naturally swept once the
	// JWT would have expired anyway. Used by POST /revoke (RFC 7009) so that a
	// revoked JWT is rejected even though JWT verification is otherwise
	// stateless.
	RevokeJTI(jti string, expiresAt time.Time) error
	// IsJTIRevoked reports whether jti is present in the (non-expired)
	// revocation denylist.
	IsJTIRevoked(jti string) bool
	// Sweep removes all expired entries. Called periodically by the Store janitor.
	Sweep() error
}

// ── in-memory RefreshTokenStore ───────────────────────────────────────────────

type memRTEntry struct {
	accessToken         string
	audience            string
	familyID            string
	expiresAt           time.Time
	revoked             bool
	nonce               string
	providerAccessToken string
}

type memRefreshTokenStore struct {
	mu              sync.RWMutex
	entries         map[string]memRTEntry // key: tokenKey(rawRefreshToken)
	revokedJTI      map[string]time.Time  // key: jti, value: expiresAt
	revokedFamilies map[string]struct{}   // key: familyID, tombstoned by RevokeFamily
}

// NewMemRefreshTokenStore returns an in-memory RefreshTokenStore.
// All data is lost when the process exits.
func NewMemRefreshTokenStore() RefreshTokenStore {
	return &memRefreshTokenStore{
		entries:         make(map[string]memRTEntry),
		revokedJTI:      make(map[string]time.Time),
		revokedFamilies: make(map[string]struct{}),
	}
}

func (m *memRefreshTokenStore) Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if familyID != "" {
		if _, revoked := m.revokedFamilies[familyID]; revoked {
			return ErrRefreshTokenFamilyRevoked
		}
	}
	m.entries[tokenKey(refreshToken)] = memRTEntry{
		accessToken: accessToken,
		audience:    audience,
		familyID:    familyID,
		expiresAt:   expiresAt,
	}
	return nil
}

func (m *memRefreshTokenStore) Lookup(refreshToken string) (string, string, string, time.Time, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.expiresAt) || e.revoked {
		return "", "", "", time.Time{}, false
	}
	return e.accessToken, e.audience, e.familyID, e.expiresAt, true
}

func (m *memRefreshTokenStore) LookupAny(refreshToken string) (string, string, string, time.Time, bool, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.expiresAt) {
		return "", "", "", time.Time{}, false, false
	}
	return e.accessToken, e.audience, e.familyID, e.expiresAt, e.revoked, true
}

func (m *memRefreshTokenStore) LookupActiveByFamily(familyID string) (string, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if familyID == "" {
		return "", false
	}
	now := time.Now()
	for _, e := range m.entries {
		if e.familyID == familyID && !e.revoked && now.Before(e.expiresAt) {
			return e.accessToken, true
		}
	}
	return "", false
}

func (m *memRefreshTokenStore) Revoke(refreshToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(refreshToken)
	e, ok := m.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil
	}
	e.revoked = true
	m.entries[key] = e
	return nil
}

func (m *memRefreshTokenStore) RevokeFamily(familyID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if familyID == "" {
		return nil
	}
	for k, e := range m.entries {
		if e.familyID == familyID && !e.revoked {
			e.revoked = true
			m.entries[k] = e
		}
	}
	// Tombstone permanently: a concurrent Save for this familyID (e.g. a
	// rotation racing this call) must be rejected rather than resurrecting
	// the family after this call returns. Never swept — mirrors the
	// rotationFailed map precedent (session.go): expected to stay small
	// since it only grows with explicit revocations.
	m.revokedFamilies[familyID] = struct{}{}
	return nil
}

func (m *memRefreshTokenStore) SaveNonce(refreshToken, nonce string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(refreshToken)
	e, ok := m.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil
	}
	e.nonce = nonce
	m.entries[key] = e
	return nil
}

func (m *memRefreshTokenStore) LookupNonce(refreshToken string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.expiresAt) {
		return ""
	}
	return e.nonce
}

func (m *memRefreshTokenStore) SaveProviderAccessToken(refreshToken, providerAccessToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := tokenKey(refreshToken)
	e, ok := m.entries[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil
	}
	e.providerAccessToken = providerAccessToken
	m.entries[key] = e
	return nil
}

func (m *memRefreshTokenStore) LookupProviderAccessToken(refreshToken string) string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	e, ok := m.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.expiresAt) {
		return ""
	}
	return e.providerAccessToken
}

func (m *memRefreshTokenStore) Delete(refreshToken string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, tokenKey(refreshToken))
	return nil
}

func (m *memRefreshTokenStore) RevokeJTI(jti string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.revokedJTI[jti] = expiresAt
	return nil
}

func (m *memRefreshTokenStore) IsJTIRevoked(jti string) bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	expiresAt, ok := m.revokedJTI[jti]
	if !ok {
		return false
	}
	return time.Now().Before(expiresAt)
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
	for jti, expiresAt := range m.revokedJTI {
		if now.After(expiresAt) {
			delete(m.revokedJTI, jti)
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
	AccessToken         string    `json:"a"`
	Audience            string    `json:"aud,omitempty"`
	FamilyID            string    `json:"fid,omitempty"`
	ExpiresAt           time.Time `json:"e"`
	Revoked             bool      `json:"rv,omitempty"`
	Nonce               string    `json:"n,omitempty"`
	ProviderAccessToken string    `json:"pat,omitempty"`
}

type fileRefreshTokenStore struct {
	mu      sync.RWMutex
	path    string
	entries map[string]fileRTEntry // key: tokenKey(rawRefreshToken)
	// revokedJTI and revokedFamilies are intentionally in-memory only (not
	// persisted to path). This legacy file-backed implementation is only
	// exercised directly by its own contract tests; the live NewHandler path
	// migrates it to sqliteRefreshTokenStore at startup (see
	// tokenstore_sqlite_migrate.go) before any /revoke traffic can occur, so
	// a durable denylist/tombstone here is unreachable in production.
	revokedJTI      map[string]time.Time
	revokedFamilies map[string]struct{}
}

// NewFileRefreshTokenStore returns a file-backed RefreshTokenStore that loads
// existing entries from path on startup and flushes atomically on every write.
// The file is created with mode 0600 (owner read/write only).
// If the file does not yet exist, an empty store is returned without error.
func NewFileRefreshTokenStore(path string) (RefreshTokenStore, error) {
	s := &fileRefreshTokenStore{
		path:            path,
		entries:         make(map[string]fileRTEntry),
		revokedJTI:      make(map[string]time.Time),
		revokedFamilies: make(map[string]struct{}),
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

func (f *fileRefreshTokenStore) Save(refreshToken, accessToken, audience, familyID string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if familyID != "" {
		if _, revoked := f.revokedFamilies[familyID]; revoked {
			return ErrRefreshTokenFamilyRevoked
		}
	}
	key := tokenKey(refreshToken)
	prev, hasPrev := f.entries[key]
	f.entries[key] = fileRTEntry{AccessToken: accessToken, Audience: audience, FamilyID: familyID, ExpiresAt: expiresAt}
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

func (f *fileRefreshTokenStore) Lookup(refreshToken string) (string, string, string, time.Time, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.ExpiresAt) || e.Revoked {
		return "", "", "", time.Time{}, false
	}
	return e.AccessToken, e.Audience, e.FamilyID, e.ExpiresAt, true
}

func (f *fileRefreshTokenStore) LookupAny(refreshToken string) (string, string, string, time.Time, bool, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return "", "", "", time.Time{}, false, false
	}
	return e.AccessToken, e.Audience, e.FamilyID, e.ExpiresAt, e.Revoked, true
}

func (f *fileRefreshTokenStore) LookupActiveByFamily(familyID string) (string, bool) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if familyID == "" {
		return "", false
	}
	now := time.Now()
	for _, e := range f.entries {
		if e.FamilyID == familyID && !e.Revoked && now.Before(e.ExpiresAt) {
			return e.AccessToken, true
		}
	}
	return "", false
}

func (f *fileRefreshTokenStore) Revoke(refreshToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(refreshToken)
	e, ok := f.entries[key]
	if !ok || time.Now().After(e.ExpiresAt) {
		return nil
	}
	prev := e
	e.Revoked = true
	f.entries[key] = e
	if err := f.flush(); err != nil {
		f.entries[key] = prev
		return err
	}
	return nil
}

func (f *fileRefreshTokenStore) RevokeFamily(familyID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if familyID == "" {
		return nil
	}
	changed := false
	for k, e := range f.entries {
		if e.FamilyID == familyID && !e.Revoked {
			e.Revoked = true
			f.entries[k] = e
			changed = true
		}
	}
	// Tombstone permanently (in-memory only — see the revokedFamilies field
	// comment) regardless of whether any row existed to revoke, so a
	// concurrent Save for this familyID is rejected either way.
	f.revokedFamilies[familyID] = struct{}{}
	if !changed {
		return nil
	}
	return f.flush()
}

func (f *fileRefreshTokenStore) SaveNonce(refreshToken, nonce string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(refreshToken)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.Nonce = nonce
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
}

func (f *fileRefreshTokenStore) LookupNonce(refreshToken string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return ""
	}
	return e.Nonce
}

func (f *fileRefreshTokenStore) SaveProviderAccessToken(refreshToken, providerAccessToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := tokenKey(refreshToken)
	entry, ok := f.entries[key]
	if !ok || time.Now().After(entry.ExpiresAt) {
		return nil
	}
	previous := entry
	entry.ProviderAccessToken = providerAccessToken
	f.entries[key] = entry
	if err := f.flush(); err != nil {
		f.entries[key] = previous
		return err
	}
	return nil
}

func (f *fileRefreshTokenStore) LookupProviderAccessToken(refreshToken string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	e, ok := f.entries[tokenKey(refreshToken)]
	if !ok || time.Now().After(e.ExpiresAt) {
		return ""
	}
	return e.ProviderAccessToken
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

func (f *fileRefreshTokenStore) RevokeJTI(jti string, expiresAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokedJTI[jti] = expiresAt
	return nil
}

func (f *fileRefreshTokenStore) IsJTIRevoked(jti string) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	expiresAt, ok := f.revokedJTI[jti]
	if !ok {
		return false
	}
	return time.Now().Before(expiresAt)
}

func (f *fileRefreshTokenStore) Sweep() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for jti, expiresAt := range f.revokedJTI {
		if now.After(expiresAt) {
			delete(f.revokedJTI, jti)
		}
	}
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
