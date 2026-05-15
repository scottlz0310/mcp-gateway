package auth

import (
	"testing"
	"time"
)

func TestLatestBySubjectEmpty(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	if _, _, ok := s.LatestBySubject(""); ok {
		t.Fatal("expected ok=false for empty subject")
	}
	if _, _, ok := s.LatestBySubject("nope"); ok {
		t.Fatal("expected ok=false for unknown subject")
	}
}

func TestLatestBySubjectReturnsCached(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.CacheToken("tok-1", "alice", "https://gw.example/mcp")

	raw, rec, ok := s.LatestBySubject("alice")
	if !ok {
		t.Fatal("expected ok=true after CacheToken")
	}
	if raw != "tok-1" {
		t.Errorf("rawToken: got %q want %q", raw, "tok-1")
	}
	if rec.Subject != "alice" {
		t.Errorf("subject: got %q want %q", rec.Subject, "alice")
	}
}

// TestLatestBySubjectPrefersProviderExpiry verifies the selection rule: when
// multiple cached tokens exist for the same subject, the entry with the
// largest provider-advertised access expiry wins (it has had a rotation
// attached, so it carries the freshest GitHub-issued credential).
func TestLatestBySubjectPrefersProviderExpiry(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.CacheToken("tok-old", "alice", "https://gw.example/mcp")
	s.CacheToken("tok-new", "alice", "https://gw.example/mcp")

	// Attach provider refresh metadata only to tok-new with a far-future
	// expiry. tok-old has no provider expiry so should be ranked lower.
	future := time.Now().Add(1 * time.Hour)
	s.RecordProviderRefresh("tok-new", "refresh-secret", future)

	raw, _, ok := s.LatestBySubject("alice")
	if !ok {
		t.Fatal("expected ok=true")
	}
	if raw != "tok-new" {
		t.Errorf("rawToken: got %q want %q (selection rule should pick the entry with provider expiry)", raw, "tok-new")
	}
}

// TestLatestBySubjectIgnoresUnknownSubjectsAfterPrune verifies that the
// subject index entry is dropped entirely once every cached token for it has
// expired, so a later lookup returns ok=false rather than a stale record.
func TestLatestBySubjectPrunesExpired(t *testing.T) {
	// Use a 1ns TTL so the entry immediately becomes expired for LatestBySubject's
	// internal "now.Before(expiresAt)" check.
	s := NewStore(10*time.Minute, 1*time.Nanosecond, NewMemTokenStore())
	s.CacheToken("tok-x", "bob", "")
	time.Sleep(10 * time.Millisecond)

	if _, _, ok := s.LatestBySubject("bob"); ok {
		t.Fatal("expected ok=false after entry expired")
	}
}
