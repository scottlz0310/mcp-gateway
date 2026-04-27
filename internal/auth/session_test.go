package auth

import (
	"testing"
	"time"
)

func TestStoreSessionLifecycle(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)

	s.SaveSession("state1", "http://localhost/cb", "")
	if !s.HasSession("state1") {
		t.Fatal("expected session to exist")
	}
	if s.HasSession("nonexistent") {
		t.Fatal("expected no session for nonexistent state")
	}
}

func TestStoreCompleteCallback(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	s.SaveSession("state2", "http://localhost/cb", "")

	code, err := s.CompleteCallback("state2", "token123", "repo,user")
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
}

func TestStoreCompleteCallbackUnknownState(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	_, err := s.CompleteCallback("nosuchstate", "tok", "")
	if err == nil {
		t.Fatal("expected error for unknown state")
	}
}

func TestStoreExchangeCodeOneTimeUse(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	s.SaveSession("state3", "http://localhost/cb", "")

	code, _ := s.CompleteCallback("state3", "tok", "")
	token, _, err := s.ExchangeCode(code, "http://localhost/cb", "")
	if err != nil {
		t.Fatalf("ExchangeCode: %v", err)
	}
	if token != "tok" {
		t.Errorf("token: got %q, want %q", token, "tok")
	}

	_, _, err = s.ExchangeCode(code, "http://localhost/cb", "")
	if err == nil {
		t.Fatal("expected error on second exchange (one-time use)")
	}
}

func TestStoreExchangeCodeRedirectURIMismatch(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	s.SaveSession("state4", "http://localhost/cb", "")

	code, _ := s.CompleteCallback("state4", "tok", "")
	_, _, err := s.ExchangeCode(code, "http://localhost/other", "")
	if err == nil {
		t.Fatal("expected error for redirect_uri mismatch")
	}
}

func TestStorePKCE(t *testing.T) {
	// RFC 7636 Appendix B test vectors.
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	s := NewStore(10*time.Minute, 5*time.Minute)
	s.SaveSession("state5", "http://localhost/cb", challenge)
	code, _ := s.CompleteCallback("state5", "tok", "")

	// Wrong verifier: code is NOT consumed on PKCE failure so we can retry.
	wrongVerifier := "wrongverifier_wrongverifier_wrongverifier_wrong"
	_, _, err := s.ExchangeCode(code, "http://localhost/cb", wrongVerifier)
	if err == nil {
		t.Fatal("expected PKCE failure with wrong verifier")
	}

	// Correct verifier should succeed.
	_, _, err = s.ExchangeCode(code, "http://localhost/cb", verifier)
	if err != nil {
		t.Fatalf("PKCE exchange with correct verifier: %v", err)
	}
}

func TestStorePKCEInvalidVerifierLength(t *testing.T) {
	challenge := "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	s := NewStore(10*time.Minute, 5*time.Minute)
	s.SaveSession("state6", "http://localhost/cb", challenge)
	code, _ := s.CompleteCallback("state6", "tok", "")

	_, _, err := s.ExchangeCode(code, "http://localhost/cb", "tooshort")
	if err == nil {
		t.Fatal("expected error for verifier that is too short")
	}
}

func TestStoreDeviceLifecycle(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	expiresAt := time.Now().Add(15 * time.Minute)

	code, err := s.CreateDevice("gh-dev-code", "ABCD-1234", "https://github.com/login/device", expiresAt, 5)
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

	s.AuthorizeDevice(code, "gha_token", "repo,user")

	d, ok = s.GetDevice(code)
	if !ok {
		t.Fatal("expected device session after authorization")
	}
	if d.Status != deviceAuthorized {
		t.Errorf("status: got %v, want authorized", d.Status)
	}
	if d.AccessToken != "gha_token" {
		t.Errorf("access_token: got %q", d.AccessToken)
	}
}

func TestStoreDeviceDeny(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)
	expiresAt := time.Now().Add(15 * time.Minute)

	code, _ := s.CreateDevice("gh-dev", "WXYZ-5678", "https://github.com/login/device", expiresAt, 5)
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
	s := NewStore(10*time.Minute, 5*time.Minute)

	_, ok := s.GetDevice("nonexistent-code")
	if ok {
		t.Fatal("expected no session for unknown code")
	}
}

func TestTokenCache(t *testing.T) {
	s := NewStore(10*time.Minute, 5*time.Minute)

	s.CacheToken("tok1", "alice")
	login, ok := s.LookupToken("tok1")
	if !ok {
		t.Fatal("expected cache hit")
	}
	if login != "alice" {
		t.Errorf("login: got %q, want %q", login, "alice")
	}

	s.InvalidateCachedToken("tok1")
	_, ok = s.LookupToken("tok1")
	if ok {
		t.Fatal("expected cache miss after invalidation")
	}
}
