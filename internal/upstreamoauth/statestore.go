package upstreamoauth

import (
	"sync"
	"time"
)

// OAuthState holds the per-authorization-request state keyed by the opaque
// state parameter. Stored in-memory and consumed exactly once on callback
// to prevent replay attacks.
type OAuthState struct {
	Subject      string    // gateway-authenticated user identity (from Auth middleware at flow start)
	RouteName    string
	OriginalPath string    // reserved for future transparent redirect restore; unused in MVP
	CodeVerifier string    // PKCE code_verifier
	ExpiresAt    time.Time // state expiry (10 minutes from creation)
}

// StateStore is a thread-safe in-memory store for upstream OAuth authorization
// states. Each state entry is consumed exactly once via Pop to prevent replay
// attacks. Expired entries are removed by Sweep.
type StateStore interface {
	Save(key string, state OAuthState)
	// Pop returns and deletes the state for key. Returns (zero, false) when
	// the key is absent or the entry has expired.
	Pop(key string) (OAuthState, bool)
	// Sweep removes all expired entries.
	Sweep()
}

type memStateStore struct {
	mu      sync.Mutex
	entries map[string]OAuthState
}

// NewStateStore returns a new in-memory StateStore.
func NewStateStore() StateStore {
	return &memStateStore{entries: make(map[string]OAuthState)}
}

func (s *memStateStore) Save(key string, state OAuthState) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = state
}

func (s *memStateStore) Pop(key string) (OAuthState, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.entries[key]
	if !ok {
		return OAuthState{}, false
	}
	delete(s.entries, key)
	if time.Now().After(state.ExpiresAt) {
		return OAuthState{}, false
	}
	return state, true
}

func (s *memStateStore) Sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for k, v := range s.entries {
		if now.After(v.ExpiresAt) {
			delete(s.entries, k)
		}
	}
}
