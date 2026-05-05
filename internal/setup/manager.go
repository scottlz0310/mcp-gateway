// Package setup implements the first-run setup wizard for mcp-gateway.
// It provides one-time token management, setup-required detection, and
// the HTTP handlers for GET/POST /setup.
package setup

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// tokenTTL is the maximum time a setup token remains valid after generation.
const tokenTTL = 15 * time.Minute

// Sentinel errors returned by Manager.Validate.
var (
	// ErrInvalidToken is returned when the provided token does not match.
	ErrInvalidToken = errors.New("setup: invalid or unknown token")
	// ErrTokenExpired is returned when the token's TTL has elapsed.
	ErrTokenExpired = errors.New("setup: token has expired; restart the gateway to obtain a new token")
	// ErrAlreadyConfigured is returned when setup has already been completed.
	ErrAlreadyConfigured = errors.New("setup: gateway is already configured")
)

// Manager holds the one-time setup token and enforces TTL and single-use semantics.
type Manager struct {
	token  string
	expiry time.Time
	mu     sync.Mutex
	done   bool
}

// New generates a cryptographically random setup token and returns a Manager
// with a 15-minute TTL.
func New() (*Manager, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("generating setup token: %w", err)
	}
	return &Manager{
		token:  hex.EncodeToString(b),
		expiry: time.Now().Add(tokenTTL),
	}, nil
}

// Token returns the setup token string (safe to log to stdout at startup).
func (m *Manager) Token() string { return m.token }

// Validate checks that token matches, has not expired, and has not yet been consumed.
func (m *Manager) Validate(token string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.done {
		return ErrAlreadyConfigured
	}
	if time.Now().After(m.expiry) {
		return ErrTokenExpired
	}
	if token != m.token {
		return ErrInvalidToken
	}
	return nil
}

// Consume marks the token as used, preventing any further /setup requests.
func (m *Manager) Consume() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.done = true
}
