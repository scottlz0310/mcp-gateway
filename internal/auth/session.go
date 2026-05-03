package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
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
	State         string
	RedirectURI   string
	CodeChallenge string
	InternalCode  string
	AccessToken   string
	Scope         string
	ExpiresAt     time.Time
}

type deviceStatus int

const (
	devicePending deviceStatus = iota
	deviceDenied                // user denied or access_denied from GitHub
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
	Status          deviceStatus
	pollingInFlight bool // true while one request is actively polling GitHub
}

// Store holds OAuth flow state (sessions, codes, devices) and delegates token
// validation persistence to a TokenStore.
type Store struct {
	mu           sync.RWMutex
	sessions     map[string]*Session
	codes        map[string]*Session
	devices      map[string]*DeviceSession // keyed by gateway-internal device code
	ttl          time.Duration

	tokens       TokenStore
	tokensTTL    time.Duration // TTL applied when saving a validated token
	refreshStore RefreshTokenStore
	refreshMu    sync.Mutex // guards atomic lookup+delete in UseRefreshToken and ReserveRefreshToken

	stopCh chan struct{}
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
		stopCh:       make(chan struct{}),
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
func (s *Store) SaveSession(state, redirectURI, codeChallenge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[state] = &Session{
		State:         state,
		RedirectURI:   redirectURI,
		CodeChallenge: codeChallenge,
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
func (s *Store) CompleteCallback(state, accessToken, scope string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.sessions[state]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.sessions, state)
		return "", fmt.Errorf("session not found or expired for state %q", state)
	}

	code, err := generateCode()
	if err != nil {
		return "", err
	}
	sess.InternalCode = code
	sess.AccessToken = accessToken
	sess.Scope = scope
	s.codes[code] = sess
	return code, nil
}

// ExchangeCode validates PKCE and returns the access token and granted scope.
// The code is consumed on success (one-time use).
func (s *Store) ExchangeCode(code, redirectURI, codeVerifier string) (string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	sess, ok := s.codes[code]
	if !ok || time.Now().After(sess.ExpiresAt) {
		delete(s.codes, code)
		return "", "", fmt.Errorf("code not found or expired")
	}
	if sess.RedirectURI != redirectURI {
		return "", "", fmt.Errorf("redirect_uri mismatch")
	}
	if sess.CodeChallenge != "" {
		if err := verifyPKCE(codeVerifier, sess.CodeChallenge); err != nil {
			return "", "", err
		}
	}

	token := sess.AccessToken
	scope := sess.Scope
	delete(s.codes, code)
	delete(s.sessions, sess.State)
	return token, scope, nil
}

// CreateDevice stores a new Device Authorization Grant session and returns the gateway-internal device code.
func (s *Store) CreateDevice(githubDevCode, userCode, verificationURI string, expiresAt time.Time, interval int) (string, error) {
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
// ReleaseDevicePolling when done. It returns false in two cases:
//
//  1. Another goroutine is already polling GitHub for the same device code
//     (pollingInFlight is true).
//  2. The device session no longer exists (e.g. it was already consumed or
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
	d.pollingInFlight = true
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
func (s *Store) CreateRefreshToken(accessToken string, ttl time.Duration) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", fmt.Errorf("generating refresh token: %w", err)
	}
	if err := s.refreshStore.Save(code, accessToken, time.Now().Add(ttl)); err != nil {
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
	accessToken, _, ok := s.refreshStore.Lookup(refreshToken)
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
	accessToken, _, ok := s.refreshStore.Lookup(refreshToken)
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
func (s *Store) ReserveRefreshToken(refreshToken string) (string, time.Time, error) {
	s.refreshMu.Lock()
	defer s.refreshMu.Unlock()
	accessToken, expiresAt, ok := s.refreshStore.Lookup(refreshToken)
	if !ok {
		return "", time.Time{}, fmt.Errorf("refresh token not found or expired")
	}
	if err := s.refreshStore.Delete(refreshToken); err != nil {
		return "", time.Time{}, fmt.Errorf("%w: %w", ErrRefreshTokenDeleteFailed, err)
	}
	return accessToken, expiresAt, nil
}

// RestoreRefreshToken puts a previously reserved refresh token back into the
// store.  Call this when the rotation flow fails after ReserveRefreshToken so
// that the client can retry without full re-authentication.
func (s *Store) RestoreRefreshToken(refreshToken, accessToken string, expiresAt time.Time) {
	if err := s.refreshStore.Save(refreshToken, accessToken, expiresAt); err != nil {
		slog.Warn("refresh token restore failed", "err", err)
	}
}

// CacheToken records that token maps to subject (e.g. GitHub login) and is valid
// for tokensTTL from now. The entry survives process restarts when a persistent
// TokenStore is configured.
func (s *Store) CacheToken(token, subject string) {
	if err := s.tokens.Save(token, subject, time.Now().Add(s.tokensTTL)); err != nil {
		// Non-fatal: next request will re-validate against the upstream provider.
		slog.Warn("token store save failed", "err", err)
	}
}

// LookupToken returns (subject, true) if token is cached and not expired.
func (s *Store) LookupToken(token string) (string, bool) {
	return s.tokens.Lookup(token)
}

// InvalidateCachedToken removes a token from the store immediately.
func (s *Store) InvalidateCachedToken(token string) {
	if err := s.tokens.Delete(token); err != nil {
		// Non-fatal: the token will expire naturally, but operators should know
		// if the store is unwritable.
		slog.Warn("token store delete failed", "err", err)
	}
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
		}
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
