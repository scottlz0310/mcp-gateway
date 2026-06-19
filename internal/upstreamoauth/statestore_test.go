package upstreamoauth_test

import (
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/upstreamoauth"
)

func TestStateStore_SaveAndPop(t *testing.T) {
	store := upstreamoauth.NewStateStore()
	state := upstreamoauth.OAuthState{
		Subject:      "user1",
		RouteName:    "route1",
		OriginalPath: "/mcp/test",
		CodeVerifier: "verifier123",
		ExpiresAt:    time.Now().Add(10 * time.Minute),
	}
	store.Save("key1", state)

	got, ok := store.Pop("key1")
	if !ok {
		t.Fatal("expected to find state")
	}
	if got.Subject != state.Subject {
		t.Errorf("Subject = %q, want %q", got.Subject, state.Subject)
	}
	if got.RouteName != state.RouteName {
		t.Errorf("RouteName = %q, want %q", got.RouteName, state.RouteName)
	}
	if got.CodeVerifier != state.CodeVerifier {
		t.Errorf("CodeVerifier = %q, want %q", got.CodeVerifier, state.CodeVerifier)
	}
}

func TestStateStore_PopConsumed(t *testing.T) {
	store := upstreamoauth.NewStateStore()
	store.Save("key", upstreamoauth.OAuthState{
		Subject:   "user",
		RouteName: "route",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})

	_, ok := store.Pop("key")
	if !ok {
		t.Fatal("first Pop: expected to find state")
	}
	// second Pop must return false (replay prevention)
	_, ok = store.Pop("key")
	if ok {
		t.Error("second Pop: expected state to be consumed after first Pop")
	}
}

func TestStateStore_NonExistentKey(t *testing.T) {
	store := upstreamoauth.NewStateStore()
	_, ok := store.Pop("nonexistent")
	if ok {
		t.Error("expected false for nonexistent key")
	}
}

func TestStateStore_ExpiredEntryRejected(t *testing.T) {
	store := upstreamoauth.NewStateStore()
	store.Save("expired-key", upstreamoauth.OAuthState{
		Subject:      "user1",
		RouteName:    "route1",
		CodeVerifier: "ver",
		ExpiresAt:    time.Now().Add(-1 * time.Minute), // already expired
	})

	_, ok := store.Pop("expired-key")
	if ok {
		t.Error("expected expired state to be rejected by Pop")
	}
}

func TestStateStore_Sweep(t *testing.T) {
	store := upstreamoauth.NewStateStore()

	store.Save("active", upstreamoauth.OAuthState{
		Subject:   "user1",
		RouteName: "route1",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	store.Save("expired1", upstreamoauth.OAuthState{
		Subject:   "user2",
		RouteName: "route1",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	})
	store.Save("expired2", upstreamoauth.OAuthState{
		Subject:   "user3",
		RouteName: "route2",
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	})

	store.Sweep()

	if _, ok := store.Pop("active"); !ok {
		t.Error("active state should survive Sweep")
	}
	if _, ok := store.Pop("expired1"); ok {
		t.Error("expired1 should be removed by Sweep")
	}
	if _, ok := store.Pop("expired2"); ok {
		t.Error("expired2 should be removed by Sweep")
	}
}
