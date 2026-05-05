package setup_test

import (
	"errors"
	"testing"
	"time"

	"github.com/scottlz0310/mcp-gateway/internal/setup"
)

func TestNew_GeneratesToken(t *testing.T) {
	mgr, err := setup.New()
	if err != nil {
		t.Fatalf("New() error: %v", err)
	}
	if len(mgr.Token()) != 32 {
		t.Errorf("token length = %d, want 32 (16 hex bytes)", len(mgr.Token()))
	}
}

func TestValidate_ValidToken(t *testing.T) {
	mgr, _ := setup.New()
	if err := mgr.Validate(mgr.Token()); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_WrongToken(t *testing.T) {
	mgr, _ := setup.New()
	err := mgr.Validate("wrongtoken")
	if err == nil {
		t.Fatal("expected error for wrong token, got nil")
	}
}

func TestValidate_AfterConsume(t *testing.T) {
	mgr, _ := setup.New()
	mgr.Consume()
	err := mgr.Validate(mgr.Token())
	if err == nil {
		t.Fatal("expected ErrAlreadyConfigured after Consume, got nil")
	}
}

func TestValidate_ExpiredToken(t *testing.T) {
	// Create a manager with a negative TTL so the token is already expired.
	mgr, err := setup.NewWithTTL(-time.Second)
	if err != nil {
		t.Fatalf("NewWithTTL: %v", err)
	}
	token := mgr.Token()
	if valErr := mgr.Validate(token); !errors.Is(valErr, setup.ErrTokenExpired) {
		t.Errorf("expected ErrTokenExpired, got %v", valErr)
	}
}
