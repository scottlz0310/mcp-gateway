package auth

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestStoreSessionLifecycle(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	s.SaveSession("state1", "http://localhost/cb", "", "https://gw.example/mcp")
	if !s.HasSession("state1") {
		t.Fatal("expected session to exist")
	}
	if s.HasSession("nonexistent") {
		t.Fatal("expected no session for nonexistent state")
	}
}

func TestStoreCompleteCallback(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.SaveSession("state2", "http://localhost/cb", "", "https://gw.example/mcp")

	code, err := s.CompleteCallback("state2", "token123", "repo,user", "", time.Time{}, "user123")
	if err != nil {
		t.Fatalf("CompleteCallback: %v", err)
	}
	if code == "" {
		t.Fatal("expected non-empty code")
	}

	sess := s.lookupByCode(code)
	if sess == nil {
		t.Fatal("expected session by code")
		return // unreachable; satisfies staticcheck SA5011
	}
	if sess.AccessToken != "token123" {
		t.Errorf("access token: got %q, want %q", sess.AccessToken, "token123")
	}
	if sess.Scope != "repo,user" {
		t.Errorf("scope: got %q, want %q", sess.Scope, "repo,user")
	}
	if sess.Audience != "https://gw.example/mcp" {
		t.Errorf("audience: got %q", sess.Audience)
	}
	if sess.Subject != "user123" {
		t.Errorf("subject: got %q, want %q", sess.Subject, "user123")
	}
}

func TestStoreCompleteCallbackUnknownState(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	const state = "secret-state-value"
	_, err := s.CompleteCallback(state, "tok", "", "", time.Time{}, "user123")
	if err == nil {
		t.Fatal("expected error for unknown state")
	}
	if strings.Contains(err.Error(), state) {
		t.Fatalf("error leaked OAuth state: %v", err)
	}
}

func TestStoreExchangeCodeOneTimeUse(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.SaveSession("state3", "http://localhost/cb", "", "https://gw.example/mcp")

	code, _ := s.CompleteCallback("state3", "tok", "", "", time.Time{}, "user123")
	result, err := s.ExchangeCode(code, "http://localhost/cb", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if result.AccessToken != "tok" {
		t.Errorf("token: got %q, want %q", result.AccessToken, "tok")
	}
	if result.Audience != "https://gw.example/mcp" {
		t.Errorf("audience: got %q", result.Audience)
	}
	if result.Subject != "user123" {
		t.Errorf("subject: got %q, want %q", result.Subject, "user123")
	}

	if _, err := s.ExchangeCode(code, "http://localhost/cb", ""); err == nil {
		t.Fatal("expected error on second exchange (one-time use)")
	}
}

func TestStoreExchangeCodeRedirectURIMismatch(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.SaveSession("state4", "http://localhost/cb", "", "https://gw.example/mcp")

	code, _ := s.CompleteCallback("state4", "tok", "", "", time.Time{}, "user123")
	if _, err := s.ExchangeCode(code, "http://localhost/other", ""); err == nil {
		t.Fatal("expected error for redirect_uri mismatch")
	}
}

func TestStorePKCE(t *testing.T) {
	// RFC 7636 Appendix B test vectors.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.SaveSession("state5", "http://localhost/cb", challenge, "https://gw.example/mcp")
	code, _ := s.CompleteCallback("state5", "tok", "", "", time.Time{}, "user123")

	// Wrong verifier: code is NOT consumed on PKCE failure so we can retry.
	wrongVerifier := "wrongverifier_wrongverifier_wrongverifier_wrong"
	if _, err := s.ExchangeCode(code, "http://localhost/cb", wrongVerifier); err == nil {
		t.Fatal("expected PKCE failure with wrong verifier")
	}

	// Correct verifier should succeed.
	if _, err := s.ExchangeCode(code, "http://localhost/cb", verifier); err != nil {
		t.Fatalf("PKCE exchange with correct verifier: %v", err)
	}
}

func TestStorePKCEInvalidVerifierLength(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	s.SaveSession("state6", "http://localhost/cb", challenge, "https://gw.example/mcp")
	code, _ := s.CompleteCallback("state6", "tok", "", "", time.Time{}, "user123")

	if _, err := s.ExchangeCode(code, "http://localhost/cb", "tooshort"); err == nil {
		t.Fatal("expected error for verifier that is too short")
	}
}

func TestStoreDeviceLifecycle(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("ABCD-1234", expiresAt, "mcp-server")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	if code == "" {
		t.Fatal("expected non-empty internal device code")
	}

	d, ok := s.GetDevice(code)
	if !ok {
		t.Fatal("expected device session to exist")
	}
	if d.UserCode != "ABCD-1234" {
		t.Errorf("user_code: got %q, want %q", d.UserCode, "ABCD-1234")
	}
	if d.Status != devicePending {
		t.Errorf("status: got %v, want pending", d.Status)
	}
	if d.Audience != "mcp-server" {
		t.Errorf("audience: got %q", d.Audience)
	}

	// Approve then consume.
	if !s.ApproveDevice(code, "gha_token", "repo,user", "alice", "", time.Time{}) {
		t.Fatal("ApproveDevice should succeed")
	}
	consumed, ok := s.ConsumeApprovedDevice(code)
	if !ok {
		t.Fatal("expected ConsumeApprovedDevice to succeed")
	}
	if consumed.AccessToken != "gha_token" {
		t.Errorf("access_token: got %q", consumed.AccessToken)
	}
	if consumed.Subject != "alice" {
		t.Errorf("subject: got %q", consumed.Subject)
	}
	if _, ok := s.GetDevice(code); ok {
		t.Error("expected device session to be removed after consuming")
	}
}

func TestStoreDeviceDeny(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("WXYZ-5678", expiresAt, "mcp-gateway")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}
	s.DenyDevice(code)

	d, ok := s.GetDevice(code)
	if !ok {
		t.Fatal("expected device session after denial")
	}
	if d.Status != deviceDenied {
		t.Errorf("status: got %v, want denied", d.Status)
	}
}

func TestStoreDeviceNotFound(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	_, ok := s.GetDevice("nonexistent-code")
	if ok {
		t.Fatal("expected no session for unknown code")
	}
}

func TestTokenCache(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	s.CacheToken("tok1", "alice", "https://gw.example/mcp")
	rec, ok := s.LookupToken("tok1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if rec.Subject != "alice" {
		t.Errorf("login: got %q, want %q", rec.Subject, "alice")
	}
	if !rec.HasAudience("https://gw.example/mcp") {
		t.Errorf("audiences: got %#v", rec.Audiences)
	}

	s.InvalidateCachedToken("tok1")
	_, ok = s.LookupToken("tok1")
	if ok {
		t.Fatal("expected cache miss after invalidation")
	}
}

// errTokenStore always returns an error from Save and Delete to exercise
// the error-logging paths in CacheToken and InvalidateCachedToken.
type errTokenStore struct{ mem *memTokenStore }

func (e *errTokenStore) Save(_, _ string, _ []string, _ time.Time) error {
	return fmt.Errorf("injected save error")
}
func (e *errTokenStore) SaveProviderRefresh(token, providerRefreshToken string, providerAccessExpiry time.Time) error {
	return e.mem.SaveProviderRefresh(token, providerRefreshToken, providerAccessExpiry)
}
func (e *errTokenStore) Lookup(token string) (TokenRecord, bool)    { return e.mem.Lookup(token) }
func (e *errTokenStore) MarkRotationFailed(_ string) error          { return nil }
func (e *errTokenStore) Delete(_ string) error                      { return fmt.Errorf("injected delete error") }
func (e *errTokenStore) Sweep() error                               { return e.mem.Sweep() }

// TestNewStoreNilTokenStore verifies that a nil TokenStore defaults to memTokenStore.
func TestNewStoreNilTokenStore(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, nil)
	s.CacheToken("tok-nil", "niluser", "https://gw.example/mcp")
	if _, ok := s.LookupToken("tok-nil"); !ok {
		t.Fatal("expected cache hit: nil TokenStore should default to mem store")
	}
}

// TestCacheTokenSaveError verifies that CacheToken logs (does not panic) when the
// underlying store returns a Save error.
func TestCacheTokenSaveError(t *testing.T) {
	ts := &errTokenStore{mem: NewMemTokenStore().(*memTokenStore)}
	s := NewStore(10*time.Minute, 5*time.Minute, ts)
	// Must not panic; error is logged via slog.Warn.
	s.CacheToken("tok-err", "user", "https://gw.example/mcp")
}

// TestInvalidateCachedTokenDeleteError verifies that InvalidateCachedToken logs
// (does not panic) when the underlying store returns a Delete error.
func TestInvalidateCachedTokenDeleteError(t *testing.T) {
	ts := &errTokenStore{mem: NewMemTokenStore().(*memTokenStore)}
	s := NewStore(10*time.Minute, 5*time.Minute, ts)
	// Must not panic; error is logged via slog.Warn.
	s.InvalidateCachedToken("tok-err")
}

func TestCreateAndUseRefreshToken(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("access-token-abc", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if rt == "" {
		t.Fatal("expected non-empty refresh token")
	}

	got, err := s.UseRefreshToken(rt)
	if err != nil {
		t.Fatalf("UseRefreshToken: %v", err)
	}
	if got != "access-token-abc" {
		t.Errorf("access token: got %q, want %q", got, "access-token-abc")
	}
}

func TestUseRefreshTokenIsOneTimeUse(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	if _, err := s.UseRefreshToken(rt); err != nil {
		t.Fatalf("first use: %v", err)
	}
	if _, err := s.UseRefreshToken(rt); err == nil {
		t.Fatal("expected error on second use (one-time use)")
	}
}

func TestUseRefreshTokenExpired(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok", "https://gw.example/mcp", "fid-1", -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	if _, err := s.UseRefreshToken(rt); err == nil {
		t.Fatal("expected error for expired refresh token")
	}
}

func TestUseRefreshTokenUnknown(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	if _, err := s.UseRefreshToken("does-not-exist"); err == nil {
		t.Fatal("expected error for unknown refresh token")
	}
}

func TestPeekRefreshTokenDoesNotConsume(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got1, err := s.PeekRefreshToken(rt)
	if err != nil {
		t.Fatalf("PeekRefreshToken: %v", err)
	}
	if got1 != "tok" {
		t.Errorf("access token: got %q", got1)
	}
	// Peek must be idempotent: token still present.
	got2, err := s.PeekRefreshToken(rt)
	if err != nil {
		t.Fatalf("second PeekRefreshToken: %v", err)
	}
	if got2 != "tok" {
		t.Errorf("access token after second peek: got %q", got2)
	}
}

func TestConsumeRefreshToken(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	s.ConsumeRefreshToken(rt)

	// Token must be gone after consumption.
	if _, err := s.PeekRefreshToken(rt); err == nil {
		t.Fatal("expected error after ConsumeRefreshToken")
	}
}

func TestConsumeRefreshTokenNoOp(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	// Must not panic on unknown token.
	s.ConsumeRefreshToken("does-not-exist")
}

func TestReserveRefreshToken(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("access-tok", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	got, audience, familyID, _, err := s.ReserveRefreshToken(rt)
	if err != nil {
		t.Fatalf("ReserveRefreshToken: %v", err)
	}
	if got != "access-tok" {
		t.Errorf("access token: got %q, want %q", got, "access-tok")
	}
	if audience != "https://gw.example/mcp" {
		t.Errorf("audience: got %q", audience)
	}
	if familyID != "fid-1" {
		t.Errorf("familyID: got %q, want %q", familyID, "fid-1")
	}
	// Token must be gone after reservation (concurrent callers must fail).
	if _, _, _, _, err2 := s.ReserveRefreshToken(rt); err2 == nil {
		t.Fatal("expected error on second ReserveRefreshToken (atomic one-time removal)")
	}
}

func TestReserveRefreshTokenExpired(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok", "https://gw.example/mcp", "fid-1", -time.Second) // already expired
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}
	if _, _, _, _, err := s.ReserveRefreshToken(rt); err == nil {
		t.Fatal("expected error for expired refresh token")
	}
}

func TestRestoreRefreshToken(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt, err := s.CreateRefreshToken("tok-restore", "https://gw.example/mcp", "fid-1", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	_, audience, familyID, expiresAt, err := s.ReserveRefreshToken(rt)
	if err != nil {
		t.Fatalf("ReserveRefreshToken: %v", err)
	}
	// Simulate rotation failure: restore the token.
	s.RestoreRefreshToken(rt, "tok-restore", audience, familyID, expiresAt)

	// Token must be accessible again via Peek after restoration.
	got, err := s.PeekRefreshToken(rt)
	if err != nil {
		t.Fatalf("PeekRefreshToken after restore: %v", err)
	}
	if got != "tok-restore" {
		t.Errorf("access token after restore: got %q, want %q", got, "tok-restore")
	}
}

// TestReserveRefreshTokenReuseRevokesFamily verifies RFC 6819 §5.2.2.3 reuse
// detection: presenting a revoked (already-used) refresh token must revoke the
// entire token family, not merely return an error for the presented token.
func TestReserveRefreshTokenReuseRevokesFamily(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	// Issue initial refresh token (rt1) with family "fid-family".
	rt1, err := s.CreateRefreshToken("at-1", "https://gw.example/mcp", "fid-family", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken rt1: %v", err)
	}

	// Normal rotation: consume rt1 → create rt2 in the same family.
	_, _, gotFID, _, err := s.ReserveRefreshToken(rt1)
	if err != nil {
		t.Fatalf("first ReserveRefreshToken: %v", err)
	}
	if gotFID != "fid-family" {
		t.Errorf("familyID: got %q, want %q", gotFID, "fid-family")
	}
	rt2, err := s.CreateRefreshToken("at-2", "https://gw.example/mcp", "fid-family", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken rt2: %v", err)
	}

	// rt1 is now revoked. Replaying it must revoke the entire family (rt2).
	_, _, _, _, err = s.ReserveRefreshToken(rt1)
	if err == nil {
		t.Fatal("expected error on revoked token replay, got nil")
	}

	// rt2 must also be revoked (family-wide invalidation).
	_, _, _, _, err = s.ReserveRefreshToken(rt2)
	if err == nil {
		t.Fatal("rt2 must be revoked after family invalidation, but ReserveRefreshToken succeeded")
	}
}

// TestReserveRefreshTokenFamilyIDPropagates verifies that the family ID is
// returned by ReserveRefreshToken and can be passed to CreateRefreshToken for
// rotation, maintaining the lineage.
func TestReserveRefreshTokenFamilyIDPropagates(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())

	rt1, err := s.CreateRefreshToken("at", "https://gw.example/mcp", "fid-chain", time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken: %v", err)
	}

	_, _, fid1, _, err := s.ReserveRefreshToken(rt1)
	if err != nil {
		t.Fatalf("ReserveRefreshToken: %v", err)
	}

	rt2, err := s.CreateRefreshToken("at-2", "https://gw.example/mcp", fid1, time.Hour)
	if err != nil {
		t.Fatalf("CreateRefreshToken rt2: %v", err)
	}

	_, _, fid2, _, err := s.ReserveRefreshToken(rt2)
	if err != nil {
		t.Fatalf("second ReserveRefreshToken: %v", err)
	}
	if fid2 != fid1 {
		t.Errorf("familyID not propagated: rt1=%q rt2=%q", fid1, fid2)
	}
}

func TestCheckAndAdvancePollIntervalEnforcesInterval(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("IJKL-0002", expiresAt, "mcp-gateway")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// First check should succeed (no nextPollAfter set yet).
	slowDown, ok := s.CheckAndAdvancePollInterval(code)
	if !ok {
		t.Fatal("expected ok=true for existing session")
	}
	if slowDown {
		t.Fatal("first check should not be slow_down")
	}

	// Second check immediately: interval not elapsed → slow_down.
	slowDown2, ok2 := s.CheckAndAdvancePollInterval(code)
	if !ok2 {
		t.Fatal("expected ok=true for existing session")
	}
	if !slowDown2 {
		t.Fatal("expected slow_down=true on second immediate check")
	}
}

func TestCheckAndAdvancePollIntervalUnknownCode(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	_, ok := s.CheckAndAdvancePollInterval("no-such-code")
	if ok {
		t.Fatal("expected ok=false for unknown code")
	}
}

func TestIncreaseDeviceInterval(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("MNOP-3333", expiresAt, "mcp-gateway")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	d, _ := s.GetDevice(code)
	before := d.Interval
	s.IncreaseDeviceInterval(code)
	d, _ = s.GetDevice(code)
	if d.Interval != before+5 {
		t.Errorf("interval after increase: got %d, want %d", d.Interval, before+5)
	}
}

func TestFindDeviceByUserCode(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	_, err := s.CreateDevice("ABCD-5678", expiresAt, "mcp-gateway")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	cases := []struct {
		input string
		found bool
	}{
		{"ABCD-5678", true},
		{"abcd-5678", true},  // case-insensitive
		{"ABCD5678", true},   // hyphen-tolerant
		{"abcd5678", true},   // both
		{"WXYZ-0000", false}, // wrong code
	}
	for _, tc := range cases {
		d, ok := s.FindDeviceByUserCode(tc.input)
		if ok != tc.found {
			t.Errorf("FindDeviceByUserCode(%q): got ok=%v, want %v", tc.input, ok, tc.found)
		}
		if ok && d.UserCode != "ABCD-5678" {
			t.Errorf("FindDeviceByUserCode(%q): got user_code=%q", tc.input, d.UserCode)
		}
	}
}

func TestConsumeApprovedDevicePreventsDoubleIssuance(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute, NewMemTokenStore())
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("QRST-1111", expiresAt, "mcp-gateway")
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// Not yet approved: ConsumeApprovedDevice should return false.
	if _, ok := s.ConsumeApprovedDevice(code); ok {
		t.Fatal("ConsumeApprovedDevice must return false for pending session")
	}

	if !s.ApproveDevice(code, "tok", "scope", "user", "", time.Time{}) {
		t.Fatal("ApproveDevice failed")
	}

	// First consume succeeds.
	if _, ok := s.ConsumeApprovedDevice(code); !ok {
		t.Fatal("first ConsumeApprovedDevice must succeed")
	}
	// Second consume must fail (already deleted).
	if _, ok := s.ConsumeApprovedDevice(code); ok {
		t.Fatal("second ConsumeApprovedDevice must return false")
	}
}
