package upstreamoauth

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ClientRecord holds the persisted upstream OAuth client registration metadata
// for a single gateway route.
type ClientRecord struct {
	RouteName             string    `json:"route_name"`
	Issuer                string    `json:"issuer"`
	AuthorizationEndpoint string    `json:"authorization_endpoint"`
	TokenEndpoint         string    `json:"token_endpoint"`
	RegistrationEndpoint  string    `json:"registration_endpoint,omitempty"`
	ClientID              string    `json:"client_id"`
	ClientSecret          string    `json:"client_secret,omitempty"`
	RegisteredAt          time.Time `json:"registered_at"`
}

// ClientStore persists upstream OAuth client registration records to a
// JSON file (upstream_clients.json). Reads and writes are safe for concurrent
// use; writes are atomic (temp file + rename, mode 0600).
type ClientStore interface {
	// Load returns the ClientRecord for routeName, or (zero, false) if absent.
	Load(routeName string) (ClientRecord, bool)
	// Save writes or replaces the record for record.RouteName atomically.
	Save(record ClientRecord) error
	// All returns a snapshot of all stored records (order unspecified).
	All() []ClientRecord
}

type fileClientStore struct {
	mu      sync.RWMutex
	path    string
	records map[string]ClientRecord // keyed by RouteName
}

// NewFileClientStore loads existing records from path and returns a ClientStore.
// If path does not exist, an empty store is returned without error.
// The file is written with mode 0600 (owner read/write only).
func NewFileClientStore(path string) (ClientStore, error) {
	s := &fileClientStore{
		path:    path,
		records: make(map[string]ClientRecord),
	}
	if err := s.load(); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("loading upstream client store %q: %w", path, err)
	}
	return s, nil
}

func (s *fileClientStore) Load(routeName string) (ClientRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.records[routeName]
	return r, ok
}

func (s *fileClientStore) Save(record ClientRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, hadPrev := s.records[record.RouteName]
	s.records[record.RouteName] = record
	if err := s.flush(); err != nil {
		if hadPrev {
			s.records[record.RouteName] = prev
		} else {
			delete(s.records, record.RouteName)
		}
		return err
	}
	return nil
}

func (s *fileClientStore) All() []ClientRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]ClientRecord, 0, len(s.records))
	for _, r := range s.records {
		out = append(out, r)
	}
	return out
}

func (s *fileClientStore) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	if len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, &s.records)
}

// flush writes s.records to disk atomically via temp file + rename.
// Must be called with s.mu held for writing.
func (s *fileClientStore) flush() error {
	data, err := json.MarshalIndent(s.records, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling upstream client store: %w", err)
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("writing upstream client store temp file: %w", err)
	}
	if err := os.Rename(tmp, s.path); err == nil {
		return nil
	}
	// Windows fallback: backup the existing file, promote the temp, remove backup.
	backup := s.path + ".bak"
	_ = os.Remove(backup)
	hadOriginal := false
	if err2 := os.Rename(s.path, backup); err2 == nil {
		hadOriginal = true
	} else if !os.IsNotExist(err2) {
		_ = os.Remove(tmp)
		return fmt.Errorf("backing up upstream client store: %w", err2)
	}
	if err2 := os.Rename(tmp, s.path); err2 != nil {
		if hadOriginal {
			if restoreErr := os.Rename(backup, s.path); restoreErr != nil {
				return fmt.Errorf("renaming upstream client store: %w (restore failed: %v)", err2, restoreErr)
			}
		}
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming upstream client store: %w", err2)
	}
	if hadOriginal {
		_ = os.Remove(backup)
	}
	return nil
}
