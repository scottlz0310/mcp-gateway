package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// ErrRefreshTokenDeleteFailed is returned by ReserveRefreshToken when the
// refresh token was found but could not be removed from the store (e.g., a
// file flush failure). The token remains usable so the client can retry.
// Callers should surface this as a transient server error, not invalid_grant.
var ErrRefreshTokenDeleteFailed = errors.New("refresh token delete failed")

// Session holds OAuth flow state between /authorize and /token.
type Session struct {
	State                 string
	RedirectURI           string
	CodeChallenge         string
	Audience              string
	InternalCode          string
	AccessToken           string
	Scope                 string
	ExpiresAt             time.Time
	ProviderRefreshToken  string    // optional GitHub refresh token (expiring tokens)
	ProviderAccessExpiry  time.Time // optional GitHub access-token expiry (zero = no expiry hint)
	Subject               string    // resolved subject
}

type deviceStatus int

const (
	devicePending deviceStatus = iota
	deviceDenied               // user denied or access_denied from GitHub
)

// DeviceSession tracks a Device Authorization Grant (RFC 8628) flow and its current status.
type DeviceSession struct {
	InternalCode    string
	GitHubDevCode   string // opaque GitHub device_code used for polling; never exposed to client
	UserCode        string
	VerificationURI string
	ExpiresAt       time.Time
	Interval        int // minimum seconds between client polls (from GitHub)
	AccessToken     string
	Scope           string
	Audience        string
	Status          deviceStatus
	pollingInFlight bool // true while one request is actively polling GitHub
	nextPollAfter   time.Time
}

// Store holds OAuth flow state (sessions, codes, devices) and delegates token
// validation persistence to a TokenStore.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	codes    map[string]*Session
	devices  map[string]*DeviceSession // keyed by gateway-internal device code
	ttl      time.Duration

	tokens       TokenStore
	tokensTTL    time.Duration // TTL applied when saving a validated token
	refreshStore RefreshTokenStore
	refreshMu    sync.Mutex // guards atomic lookup+delete in UseRefreshToken and ReserveRefreshToken

	// subjectIndex maps a subject (e.g. GitHub login) to the raw access
	// tokens currently cached for that subject. Used by the Phase B
	// delegated-access internal API (#72) so background upstream workers
	// can fetch the latest valid token for a known user. The index is
	// **in-memory only**: the file-backed token store stores only token
	// hashes, so a persistent reverse index would require duplicating
	// raw tokens to disk — out of scope for the PoC.
	subjectIndexMu sync.RWMutex
	subjectIndex   map[string][]subjectIndexEntry

	// rotationFailed tracks raw tokens for which a permanent provider
	// rotation failure has been observed (e.g. bad_refresh_token,
	// revoked credentials). Keys are SHA-256 hashes (tokenKey) of raw
	// bearers. In-memory only: on gateway restart the set is empty and
	// the permanent failure will be re-recorded on the first attempted
	// rotation. The map is never explicitly pruned — it grows at most
	// as large as the number of tokens that ever hit a permanent failure,
	// which is expected to be small.
	rotationFailedMu sync.RWMutex
	rotationFailed   map[string]struct{}

	stopCh chan struct{}
}

// subjectIndexEntry is one (subject, rawToken) mapping kept by Store.
// expiresAt is the gateway cache TTL used both for pruning and as a
// fallback ranking key when no entry has provider rotation metadata.
// The authoritative ProviderAccessExpiry lives on the TokenRecord
// itself; we do **not** mirror it here because the copy can drift
// (e.g. after ClearProviderRefresh wipes the underlying metadata).
type subjectIndexEntry struct {
	rawToken  string
	expiresAt time.Time
}

// StoreOption configures optional behaviour of NewStore.
type StoreOption func(*Store)

// WithRefreshTokenStore overrides the RefreshTokenStore used by the Store.
// When not provided, an in-memory store is used (data lost on restart).
// Passing nil is a no-op; the default in-memory store is kept.
func WithRefreshTokenStore(rts RefreshTokenStore) StoreOption {
	return func(s *Store) {
		if rts != nil {
			s.refreshStore = rts
		}
	}
}

// NewStore creates a Store with the given session TTL and TokenStore, then
// starts a background janitor.
func NewStore(sessionTTL, tokensTTL time.Duration, ts TokenStore, opts ...StoreOption) *Store {
	if ts == nil {
		ts = NewMemTokenStore()
	}
	s := &Store{
		sessions:     make(map[string]*Session),
		codes:        make(map[string]*Session),
		devices:      make(map[string]*DeviceSession),
		ttl:          sessionTTL,
		tokens:       ts,
		tokensTTL:    tokensTTL,
		refreshStore: NewMemRefreshTokenStore(),
		subjectIndex:   make(map[string][]subjectIndexEntry),
		rotationFailed: make(map[string]struct{}),
		stopCh:         make(chan struct{}),
	}
	for _, opt := range opts {
		opt(s)
	}
	go s.janitor()
	return s
}

// Stop terminates the background janitor goroutine.
func (s *Store) Stop() {
	close(s.stopCh)
}

// SaveSession stores a new OAuth session keyed by state.
func (s *Store) SaveSession(state, redirectURI, codeChallenge, audience string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[state] = &Session{
		State:         state,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
		Audience:      audience,
		ExpiresAt:     time.Now().Add(s.ttl),
	}
}

// HasSession returns true if state maps to a live (non-expired) session.
func (s *Store) HasSession(state string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	sess, ok := s.sessions[state]
	return ok && !time.Now().After(sess.ExpiresAt)
}

// CompleteCallback attaches an internal code and access token to the session.
// providerRefreshToken and providerAccessExpiry are zero-valued when the
// upstream provider did not advertise them (e.g. classic non-expiring GitHub
// OAuth tokens).
func (s *Store) CompleteCallback(state, accessToken, scope, providerRefreshToken string, providerAccessExpiry time.Time, subject string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[state]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, state)
		return "", errors.New("session not found or expired")
	}

	code, err := generateCode()
	if err != nil {
		return "", err
	}
	sess.InternalCode = code
	sess.AccessToken = accessToken
	sess.Scope = scope
	sess.ProviderRefreshToken = providerRefreshToken
	sess.ProviderAccessExpiry = providerAccessExpiry
	sess.Subject = subject
	s.codes[code] = sess
	return code, nil
}

// ExchangeCodeResult bundles the values returned by Store.ExchangeCode so
// callers can pick up provider-issued refresh metadata without growing the
// function signature past five return values.
type ExchangeCodeResult struct {
	AccessToken          string
	Scope                string
	Audience             string
	ProviderRefreshToken string
	ProviderAccessExpiry time.Time
	Subject              string    // resolved subject
}

// ExchangeCode validates PKCE and returns the access token, granted scope, and
// requested audience along with any upstream provider refresh metadata.  The
// code is consumed on success (one-time use).
func (s *Store) ExchangeCode(code, redirectURI, codeVerifier string) (ExchangeCodeResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.codes[code]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.codes, code)
		return ExchangeCodeResult{}, fmt.Errorf("code not found or expired")
	}
	if sess.RedirectURI != redirectURI {
		return ExchangeCodeResult{}, fmt.Errorf("redirect_uri mismatch")
	}
	if sess.CodeChallenge != "" {
		if err := verifyPKCE(codeVerifier, sess.CodeChallenge); err != nil {
			return ExchangeCodeResult{}, err
		}
	}

	result := ExchangeCodeResult{
		AccessToken:          sess.AccessToken,
		Scope:                sess.Scope,
		Audience:             sess.Audience,
		ProviderRefreshToken: sess.ProviderRefreshToken,
		ProviderAccessExpiry: sess.ProviderAccessExpiry,
		Subject:              sess.Subject,
	}
	delete(s.codes, code)
	delete(s.sessions, sess.State)
	return result, nil
}

// CreateDevice stores a new Device Authorization Grant session and returns the gateway-internal device code.
func (s *Store) CreateDevice(githubDevCode, userCode, verificationURI string, expiresAt time.Time, interval int, audience string) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[code] = &DeviceSession{
		InternalCode:    code,
		GitHubDevCode:   githubDevCode,
		UserCode:        userCode,
		VerificationURI: verificationURI,
		ExpiresAt:       expiresAt,
		Interval:        interval,
		Audience:        audience,
		Status:          devicePending,
	}
	return code, nil
}

// GetDevice returns a copy of the DeviceSession for the given internal device code.
func (s *Store) GetDevice(internalCode string) (DeviceSession, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[internalCode]
	if !ok {
		return DeviceSession{}, false
	}
	return *d, true
}

// AuthorizeAndConsumeDevice atomically records the access token and removes the device session.
// Returns the updated session and true on success, or zero value and false if already consumed.
func (s *Store) AuthorizeAndConsumeDevice(internalCode, accessToken, scope string) (DeviceSession, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[internalCode]
	if !ok {
		return DeviceSession{}, false
	}
	d.AccessToken = accessToken
	d.Scope = scope
	result := *d
	delete(s.devices, internalCode)
	return result, true
}

// DenyDevice marks the device session as denied by the user.
func (s *Store) DenyDevice(internalCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[internalCode]; ok {
		d.Status = deviceDenied
	}
}

// AcquireDevicePolling atomically marks the device session as in-flight for
// GitHub polling. It returns true when the caller wins the race and must call
// ReleaseDevicePolling when done. Winning also reserves the next provider poll
// slot for the device's interval, so a fast follow-up request cannot hit GitHub
// inside the interval and trigger slow_down.
//
// It returns false in three cases:
//
//  1. Another goroutine is already polling GitHub for the same device code
//     (pollingInFlight is true).
//  2. The previous provider poll happened less than Interval seconds ago.
//  3. The device session no longer exists (e.g. it was already consumed or
//     expired and cleaned up by the janitor).
//
// Callers should distinguish these cases by re-reading the session state when
// false is returned.
func (s *Store) AcquireDevicePolling(internalCode string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[internalCode]
	if !ok {
		return false
	}
	if d.pollingInFlight {
		return false
	}
	now := time.Now()
	if !d.nextPollAfter.IsZero() && now.Before(d.nextPollAfter) {
		return false
	}
	d.pollingInFlight = true
	if d.Interval > 0 {
		d.nextPollAfter = now.Add(time.Duration(d.Interval) * time.Second)
	}
	return true
}

// ReleaseDevicePolling clears the in-flight flag set by AcquireDevicePolling.
// It is a no-op when the device session no longer exists (e.g. consumed).
func (s *Store) ReleaseDevicePolling(internalCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[internalCode]; ok {
		d.pollingInFlight = false
	}
}

// CreateRefreshToken generates a gateway-issued refresh token for the given
// accessToken and stores it with the supplied TTL. The refresh token is an
// opaque random string. When a file-backed RefreshTokenStore is configured
// (MCP_GATEWAY_TOKEN_STORE_PATH is set), the associated access token value is
// written to disk in the .refresh sibling file (mode 0600); see the
// MCP_GATEWAY_TOKEN_STORE_PATH documentation for security considerations.
func (s *Store) CreateRefreshToken(accessToken, audience string, ttl time.Duration) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	if err := s.refreshStore.Save(code, accessToken, audience, time.Now().Add(ttl)); err != nil {
		return "", fmt.Errorf("saving refresh token: %w", err)
	}
	return code, nil
}

// UseRefreshToken atomically looks up and removes a refresh token.
// Returns the associated access token on success, or an error when the token
// is unknown or has expired.  Callers must issue a replacement refresh token
// (rotation) before returning a token response.
func (s *Store) UseRefreshToken(refreshToken string) (string, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	accessToken, _, _, ok := s.refreshStore.Lookup(refreshToken)
	if !ok {
		return "", fmt.Errorf("refresh token not found or expired")
	}
	if err := s.refreshStore.Delete(refreshToken); err != nil {
		return "", fmt.Errorf("deleting refresh token: %w", err)
	}
	return accessToken, nil
}

// PeekRefreshToken looks up a refresh token and validates its expiry without
// consuming it.  Returns the associated access token on success, or an error
// when the token is unknown or has expired.  Use ConsumeRefreshToken to
// delete the token only after the full rotation has succeeded.
func (s *Store) PeekRefreshToken(refreshToken string) (string, error) {
	accessToken, _, _, ok := s.refreshStore.Lookup(refreshToken)
	if !ok {
		return "", fmt.Errorf("refresh token not found or expired")
	}
	return accessToken, nil
}

// ConsumeRefreshToken removes a refresh token from the store.
// It is a no-op when the token is not present.
func (s *Store) ConsumeRefreshToken(refreshToken string) {
	if err := s.refreshStore.Delete(refreshToken); err != nil {
		slog.Warn("refresh token delete failed", "err", err)
	}
}

// ReserveRefreshToken atomically removes a refresh token from the store and
// returns the associated access token and expiry time.  Because the token is
// deleted immediately, concurrent callers presenting the same token will
// receive an error here, preventing double-rotation.  On any subsequent
// failure in the rotation flow, call RestoreRefreshToken to put the token
// back so the client can retry.
func (s *Store) ReserveRefreshToken(refreshToken string) (string, string, time.Time, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	accessToken, audience, expiresAt, ok := s.refreshStore.Lookup(refreshToken)
	if !ok {
		return "", "", time.Time{}, fmt.Errorf("refresh token not found or expired")
	}
	if err := s.refreshStore.Delete(refreshToken); err != nil {
		return "", "", time.Time{}, fmt.Errorf("%w: %w", ErrRefreshTokenDeleteFailed, err)
	}
	return accessToken, audience, expiresAt, nil
}

// RestoreRefreshToken puts a previously reserved refresh token back into the
// store.  Call this when the rotation flow fails after ReserveRefreshToken so
// that the client can retry without full re-authentication.
func (s *Store) RestoreRefreshToken(refreshToken, accessToken, audience string, expiresAt time.Time) {
	if err := s.refreshStore.Save(refreshToken, accessToken, audience, expiresAt); err != nil {
		slog.Warn("refresh token restore failed", "err", err)
	}
}

// RegisterTokenAudience records the audience granted to a newly issued token.
// The subject may be filled later after the first provider validation.
func (s *Store) RegisterTokenAudience(token, audience string) {
	s.saveTokenRecord(token, "", audience)
}

// CacheToken records that token maps to subject (e.g. GitHub login) and merges
// any supplied audience. The entry survives process restarts when a persistent
// TokenStore is configured.
func (s *Store) CacheToken(token, subject, audience string) {
	s.saveTokenRecord(token, subject, audience)
}

func (s *Store) saveTokenRecord(token, subject, audience string) {
	var audiences []string
	if audience != "" {
		audiences = []string{audience}
	}
	expiresAt := time.Now().Add(s.tokensTTL)
	if err := s.tokens.Save(token, subject, audiences, expiresAt); err != nil {
		// Non-fatal: next request will re-validate against the upstream provider.
		slog.Warn("token store save failed", "err", err)
	}
	if subject != "" {
		s.indexSubjectToken(subject, token, expiresAt)
	}
}

// indexSubjectToken records that the raw access token belongs to subject in
// the in-memory subject index. The provider-side expiry is intentionally not
// mirrored here; LatestBySubject reads it from the authoritative TokenRecord
// instead, so the index stays as small as possible.
func (s *Store) indexSubjectToken(subject, rawToken string, expiresAt time.Time) {
	s.subjectIndexMu.Lock()
	defer s.subjectIndexMu.Unlock()
	entries := s.subjectIndex[subject]
	// De-duplicate by raw token (same token can be cached multiple times
	// on repeated client requests; keep the latest expiry).
	for i, e := range entries {
		if e.rawToken == rawToken {
			entries[i].expiresAt = expiresAt
			s.subjectIndex[subject] = entries
			return
		}
	}
	s.subjectIndex[subject] = append(entries, subjectIndexEntry{
		rawToken:  rawToken,
		expiresAt: expiresAt,
	})
}

// RefreshSubjectIndex re-seeds the in-memory subject → token index for a
// token that is already present in the authoritative TokenStore. It is
// idempotent and uses recordExpiresAt (the authoritative TokenRecord's
// ExpiresAt) as the index entry's expiresAt, so the index never outlives
// the underlying record.
//
// The intended caller is the cache-hit branch of ValidateToken: after a
// process restart with a persistent TokenStore the in-memory
// subjectIndex is empty even though records exist on disk, and a normal
// proxied request that hits the cache would otherwise never re-populate
// the index — leaving /internal/v1/whoami returning subject_not_found
// until a cache miss or rotation eventually triggers CacheToken.
//
// Callers that perform a full cache write should use CacheToken (which
// also refreshes the index via saveTokenRecord) rather than this method.
func (s *Store) RefreshSubjectIndex(subject, rawToken string, recordExpiresAt time.Time) {
	if subject == "" || rawToken == "" || recordExpiresAt.IsZero() {
		return
	}
	s.indexSubjectToken(subject, rawToken, recordExpiresAt)
}

// LatestBySubject returns the raw access token with the latest provider
// access expiry for the given subject, along with its cached TokenRecord.
// Returns ok=false when no live entry exists. Used by the Phase B internal
// delegated-access API.
//
// Selection rule: prefer the entry whose **authoritative TokenRecord**
// carries the largest non-zero ProviderAccessExpiry; fall back to the
// largest cache expiresAt when no entry has rotation metadata (classic
// non-expiring tokens). We rank on the authoritative record rather than
// the subject-index hint because the latter is a copy that can drift
// (e.g. after ClearProviderRefresh wipes provider metadata in the token
// store but the hint is still present in RAM).
func (s *Store) LatestBySubject(subject string) (string, TokenRecord, bool) {
	if subject == "" {
		return "", TokenRecord{}, false
	}
	s.subjectIndexMu.Lock()
	entries := s.subjectIndex[subject]
	now := time.Now()
	// Prune expired entries by building a fresh slice. Reusing the original
	// backing array (entries[:0]) would keep references to skipped raw
	// tokens alive whenever any live entry remains, which matters here
	// because these strings are bearer tokens.
	live := make([]subjectIndexEntry, 0, len(entries))
	for _, e := range entries {
		if now.Before(e.expiresAt) {
			live = append(live, e)
		}
	}
	if len(live) == 0 {
		delete(s.subjectIndex, subject)
		s.subjectIndexMu.Unlock()
		return "", TokenRecord{}, false
	}
	s.subjectIndex[subject] = live
	// Snapshot under lock; copy out before releasing to avoid races.
	candidates := make([]subjectIndexEntry, len(live))
	copy(candidates, live)
	s.subjectIndexMu.Unlock()

	var best subjectIndexEntry
	var bestRec TokenRecord
	foundRotatable := false
	// Track entries that should be pruned from the index because their
	// authoritative record disappeared or has been re-associated with a
	// different subject. These index entries hold raw bearer tokens, so
	// leaving them in place would let stale credentials linger until the
	// index TTL expires.
	//
	// We snapshot each stale candidate's expiresAt as well, so the prune
	// pass can refuse to drop an entry whose expiresAt has since been
	// bumped by a concurrent CacheToken/indexSubjectToken (i.e. another
	// request re-validated the same raw token between our snapshot here
	// and the prune below). Without this guard the freshly re-indexed
	// entry would be dropped and delegated lookups would return
	// subject_not_found until re-auth.
	stale := make(map[string]time.Time)
	for _, e := range candidates {
		rec, ok := s.tokens.Lookup(e.rawToken)
		if !ok {
			stale[e.rawToken] = e.expiresAt
			continue
		}
		// Defense-in-depth: skip records whose authoritative Subject
		// disagrees with the requested subject. The subject index is
		// only updated via indexSubjectToken (called from CacheToken),
		// so a mismatch here would indicate the raw token was re-cached
		// under a different subject after we indexed it -- in which
		// case the index entry is stale and must not be returned, lest
		// we hand out another subject's bearer.
		if rec.Subject != "" && rec.Subject != subject {
			stale[e.rawToken] = e.expiresAt
			continue
		}
		// Rank against the authoritative record so a stale subject-index
		// hint (e.g. cleared metadata after a permanent rotation failure)
		// cannot cause us to prefer an unrotatable token.
		if !rec.ProviderAccessExpiry.IsZero() {
			if !foundRotatable || rec.ProviderAccessExpiry.After(bestRec.ProviderAccessExpiry) ||
				(foundRotatable && rec.ProviderAccessExpiry.Equal(bestRec.ProviderAccessExpiry)) {
				best = e
				bestRec = rec
				foundRotatable = true
			}
			continue
		}
		if foundRotatable {
			continue
		}
		if best.rawToken == "" || e.expiresAt.After(best.expiresAt) {
			best = e
			bestRec = rec
		}
	}
	if len(stale) > 0 {
		s.pruneSubjectIndexEntries(subject, stale)
	}
	if best.rawToken == "" {
		return "", TokenRecord{}, false
	}
	return best.rawToken, bestRec, true
}

// pruneSubjectIndexEntries removes the given raw tokens from subject's index
// slice. Used by LatestBySubject to drop entries whose authoritative
// TokenStore lookup failed or whose Subject was re-assigned, so stale bearer
// strings do not remain reachable for the rest of the index TTL.
//
// snapshotExpiry maps rawToken to the expiresAt observed when the entry was
// identified as stale. If a concurrent CacheToken/indexSubjectToken has since
// updated the live entry's expiresAt (re-validating the same raw token), the
// snapshot will not match the live value and we skip the drop — otherwise we
// would delete a freshly-validated entry and cause delegated lookups to fail
// until the user re-authenticates.
func (s *Store) pruneSubjectIndexEntries(subject string, snapshotExpiry map[string]time.Time) {
	if len(snapshotExpiry) == 0 {
		return
	}
	s.subjectIndexMu.Lock()
	defer s.subjectIndexMu.Unlock()
	entries := s.subjectIndex[subject]
	if len(entries) == 0 {
		return
	}
	kept := make([]subjectIndexEntry, 0, len(entries))
	for _, e := range entries {
		snap, marked := snapshotExpiry[e.rawToken]
		if marked && e.expiresAt.Equal(snap) {
			continue
		}
		kept = append(kept, e)
	}
	if len(kept) == 0 {
		delete(s.subjectIndex, subject)
		return
	}
	s.subjectIndex[subject] = kept
}

// LookupToken returns cached metadata if token is known and not expired.
func (s *Store) LookupToken(token string) (TokenRecord, bool) {
	return s.tokens.Lookup(token)
}

// RecordProviderRefresh attaches provider-issued refresh metadata (GitHub OAuth
// refresh token + access expiry) to an already-cached token entry. It is a
// no-op when providerRefreshToken is empty or when the underlying cache entry
// is missing; the latter happens when CacheToken has not yet run for this
// token, in which case the metadata is intentionally dropped rather than
// overwriting unrelated state.
func (s *Store) RecordProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) {
	if strings.TrimSpace(providerRefreshToken) == "" {
		return
	}
	if err := s.tokens.SaveProviderRefresh(token, providerRefreshToken, providerAccessExpiry); err != nil {
		slog.Warn("token store provider refresh save failed", "err", err)
		return
	}
	// LatestBySubject ranks on the authoritative TokenRecord, so there
	// is no separate index hint to update here.
}

// ClearProviderRefresh drops the provider refresh metadata for token (sets
// both the refresh token and access expiry to their zero values). Used after
// a permanent rotation failure (e.g. bad_refresh_token) so subsequent
// ValidateToken calls do not re-attempt rotation until the entry is rebuilt
// by a fresh OAuth flow.
func (s *Store) ClearProviderRefresh(token string) {
	if err := s.tokens.SaveProviderRefresh(token, "", time.Time{}); err != nil {
		slog.Warn("token store provider refresh clear failed", "err", err)
	}
}

// MarkRotationPermanentlyFailed records a permanent rotation failure for
// token. It first persists a durable RotationPermanentlyFailed flag in the
// token store. If that flush fails, the function updates in-memory state only
// (subject index eviction + rotationFailed map) and returns without clearing
// provider refresh metadata — this guarantees the file store is never left in
// the non-durable intermediate state (cleared metadata, no flag) that would
// allow a dead bearer to be re-seeded after a gateway restart. The next
// rotation attempt will retry the flush and eventually converge.
//
// When the flush succeeds, ClearProviderRefresh is called next, then the
// token is removed from the subject index so EnsureFreshAccessTokenForSubject
// cannot return it via the lenient branch, and an in-memory flag is set for
// belt-and-suspenders protection within the same process.
//
// After a gateway restart with a file-backed store, the
// RotationPermanentlyFailed flag is restored from disk and ValidateToken
// skips RefreshSubjectIndex, so the dead bearer is never re-inserted into
// the subject index.
func (s *Store) MarkRotationPermanentlyFailed(token string) {
	// Persist the durable flag FIRST. If the flush fails, do not proceed to
	// ClearProviderRefresh: leaving cleared metadata on disk without the
	// RotationPermanentlyFailed flag recreates the original restart bug
	// (ValidateToken re-seeds the subject index → dead bearer returned).
	// On flush failure we still update in-memory state so the dead bearer is
	// blocked within this process; the next rotation attempt will retry the
	// flush and eventually converge.
	if err := s.tokens.MarkRotationFailed(token); err != nil {
		slog.Warn("token store mark rotation failed; not clearing metadata to preserve durable-state invariant", "err", err)
		if rec, ok := s.tokens.Lookup(token); ok && rec.Subject != "" {
			s.removeSubjectIndexEntry(rec.Subject, token)
		}
		s.rotationFailedMu.Lock()
		s.rotationFailed[tokenKey(token)] = struct{}{}
		s.rotationFailedMu.Unlock()
		return
	}
	s.ClearProviderRefresh(token)
	// Remove from subject index so EnsureFreshAccessTokenForSubject cannot
	// serve the dead bearer via the lenient branch (no rotation metadata).
	if rec, ok := s.tokens.Lookup(token); ok && rec.Subject != "" {
		s.removeSubjectIndexEntry(rec.Subject, token)
	}
	s.rotationFailedMu.Lock()
	s.rotationFailed[tokenKey(token)] = struct{}{}
	s.rotationFailedMu.Unlock()
}

// IsRotationPermanentlyFailed reports whether a permanent rotation failure
// has been recorded for the given raw token.
func (s *Store) IsRotationPermanentlyFailed(token string) bool {
	s.rotationFailedMu.RLock()
	_, failed := s.rotationFailed[tokenKey(token)]
	s.rotationFailedMu.RUnlock()
	return failed
}

// InvalidateCachedToken removes a token from the store immediately.
func (s *Store) InvalidateCachedToken(token string) {
	// Capture the subject before deletion so we can drop the matching
	// subject-index entry too. Without this, an invalidated bearer would
	// linger in RAM (and be visible to LatestBySubject) until the cache
	// TTL or the janitor sweep removed it.
	var subject string
	if rec, ok := s.tokens.Lookup(token); ok {
		subject = rec.Subject
	}
	if err := s.tokens.Delete(token); err != nil {
		// Non-fatal: the token will expire naturally, but operators should know
		// if the store is unwritable.
		slog.Warn("token store delete failed", "err", err)
	}
	if subject != "" {
		s.removeSubjectIndexEntry(subject, token)
	}
}

// removeSubjectIndexEntry drops the entry matching rawToken from subject's
// in-memory index. Builds a fresh slice rather than reusing the backing
// array so the dropped bearer string is released for GC promptly.
func (s *Store) removeSubjectIndexEntry(subject, rawToken string) {
	s.subjectIndexMu.Lock()
	defer s.subjectIndexMu.Unlock()
	entries, ok := s.subjectIndex[subject]
	if !ok {
		return
	}
	out := make([]subjectIndexEntry, 0, len(entries))
	for _, e := range entries {
		if e.rawToken == rawToken {
			continue
		}
		out = append(out, e)
	}
	if len(out) == 0 {
		delete(s.subjectIndex, subject)
		return
	}
	s.subjectIndex[subject] = out
}

func (s *Store) janitor() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			now := time.Now()
			s.mu.Lock()
			for k, v := range s.sessions {
				if now.After(v.ExpiresAt) {
					delete(s.sessions, k)
				}
			}
			for k, v := range s.codes {
				if now.After(v.ExpiresAt) {
					delete(s.codes, k)
				}
			}
			for k, v := range s.devices {
				if now.After(v.ExpiresAt) {
					delete(s.devices, k)
				}
			}
			s.mu.Unlock()

			if err := s.tokens.Sweep(); err != nil {
				slog.Warn("token store sweep failed", "err", err)
			}
			if err := s.refreshStore.Sweep(); err != nil {
				slog.Warn("refresh token store sweep failed", "err", err)
			}
			s.sweepSubjectIndex(now)
		}
	}
}

// sweepSubjectIndex drops expired entries and any subject whose token list
// is empty after pruning. Cheap O(n) scan; the index is expected to be small
// relative to the token store (one entry per subject per active rotation).
// Expired entries are also removed from the rotationFailed map to keep it
// bounded.
func (s *Store) sweepSubjectIndex(now time.Time) {
	// Collect expired token keys outside the subject-index lock so we
	// can acquire the rotationFailed lock separately without nesting.
	var expiredKeys []string

	s.subjectIndexMu.Lock()
	for subject, entries := range s.subjectIndex {
		// Build a fresh slice instead of reusing the backing array. These
		// entries hold raw bearer tokens; reusing entries[:0] would keep
		// the skipped (expired) tokens reachable via the array's tail for
		// as long as any live entry remained.
		live := make([]subjectIndexEntry, 0, len(entries))
		for _, e := range entries {
			if now.Before(e.expiresAt) {
				live = append(live, e)
			} else {
				expiredKeys = append(expiredKeys, tokenKey(e.rawToken))
			}
		}
		if len(live) == 0 {
			delete(s.subjectIndex, subject)
			continue
		}
		s.subjectIndex[subject] = live
	}
	s.subjectIndexMu.Unlock()

	if len(expiredKeys) > 0 {
		s.rotationFailedMu.Lock()
		for _, k := range expiredKeys {
			delete(s.rotationFailed, k)
		}
		s.rotationFailedMu.Unlock()
	}
}

// lookupByCode is used by Callback to read redirect_uri without consuming the code.
func (s *Store) lookupByCode(code string) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.codes[code]
}

func generateCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating code: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// isValidPKCEVerifier checks RFC 7636 requirements: 43–128 chars, unreserved charset only.
func isValidPKCEVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if (c >= 'A' && c <= 'Z') ||
			(c >= 'a' && c <= 'z') ||
			(c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

func verifyPKCE(verifier, challenge string) error {
	if !isValidPKCEVerifier(verifier) {
		return fmt.Errorf("invalid_grant")
	}
	h := sha256.Sum256([]byte(verifier))
	got := base64.RawURLEncoding.EncodeToString(h[:])
	if got != challenge {
		return fmt.Errorf("PKCE verification failed")
	}
	return nil
}
