package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

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
	devicePending    deviceStatus = iota
	deviceAuthorized              // GitHub returned access_token
	deviceDenied                  // user denied or access_denied from GitHub
)

// DevicePending tracks an in-progress Device Authorization Grant (RFC 8628) flow.
type DevicePending struct {
	InternalCode  string
	GitHubDevCode string // opaque GitHub device_code used for polling; never exposed to client
	UserCode      string
	VerifyURI     string
	ExpiresAt     time.Time
	Interval      int // minimum seconds between client polls (from GitHub)
	AccessToken   string
	Scope         string
	Status        deviceStatus
}

type tokenEntry struct {
	login     string
	expiresAt time.Time
}

// TokenCache caches validated GitHub tokens to reduce API calls.
type TokenCache struct {
	mu      sync.RWMutex
	entries map[string]tokenEntry
}

// Store holds OAuth sessions and the token validation cache.
type Store struct {
	mu       sync.RWMutex
	sessions map[string]*Session
	codes    map[string]*Session
	devices  map[string]*DevicePending // keyed by gateway-internal device code
	ttl      time.Duration

	cache    *TokenCache
	cacheTTL time.Duration

	stopCh chan struct{}
}

// NewStore creates a Store with the given TTLs and starts a background janitor.
func NewStore(sessionTTL, cacheTTL time.Duration) *Store {
	s := &Store{
		sessions: make(map[string]*Session),
		codes:    make(map[string]*Session),
		devices:  make(map[string]*DevicePending),
		ttl:      sessionTTL,
		cache:    &TokenCache{entries: make(map[string]tokenEntry)},
		cacheTTL: cacheTTL,
		stopCh:   make(chan struct{}),
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
func (s *Store) CreateDevice(githubDevCode, userCode, verifyURI string, expiresAt time.Time, interval int) (string, error) {
	code, err := generateCode()
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.devices[code] = &DevicePending{
		InternalCode:  code,
		GitHubDevCode: githubDevCode,
		UserCode:      userCode,
		VerifyURI:     verifyURI,
		ExpiresAt:     expiresAt,
		Interval:      interval,
		Status:        devicePending,
	}
	return code, nil
}

// GetDevice returns a copy of the DevicePending for the given internal device code.
func (s *Store) GetDevice(internalCode string) (DevicePending, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	d, ok := s.devices[internalCode]
	if !ok {
		return DevicePending{}, false
	}
	return *d, true
}

// AuthorizeDevice marks the device session as authorized with the given token.
func (s *Store) AuthorizeDevice(internalCode, accessToken, scope string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[internalCode]; ok {
		d.AccessToken = accessToken
		d.Scope = scope
		d.Status = deviceAuthorized
	}
}

// DenyDevice marks the device session as denied by the user.
func (s *Store) DenyDevice(internalCode string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if d, ok := s.devices[internalCode]; ok {
		d.Status = deviceDenied
	}
}

// CacheToken stores a validated login for a token.
func (s *Store) CacheToken(token, login string) {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	s.cache.entries[token] = tokenEntry{login: login, expiresAt: time.Now().Add(s.cacheTTL)}
}

// LookupToken returns (login, true) if token is cached and not expired.
func (s *Store) LookupToken(token string) (string, bool) {
	s.cache.mu.RLock()
	defer s.cache.mu.RUnlock()
	e, ok := s.cache.entries[token]
	if !ok || time.Now().After(e.expiresAt) {
		return "", false
	}
	return e.login, true
}

// InvalidateCachedToken removes a token from the cache immediately.
func (s *Store) InvalidateCachedToken(token string) {
	s.cache.mu.Lock()
	defer s.cache.mu.Unlock()
	delete(s.cache.entries, token)
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

			s.cache.mu.Lock()
			for k, v := range s.cache.entries {
				if now.After(v.expiresAt) {
					delete(s.cache.entries, k)
				}
			}
			s.cache.mu.Unlock()
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
