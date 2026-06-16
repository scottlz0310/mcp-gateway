package provider

import (
	"testing"
)

func TestNewBuiltinProvider(t *testing.T) {
	cases := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid builtin config",
			cfg: Config{
				Kind:         "builtin",
				ClientID:     "cid",
				ClientSecret: "secret",
				RedirectURI:  "http://localhost:8080/callback",
				Scopes:       "read:user,user:email",
			},
			wantErr: false,
		},
		{
			name: "builtin missing ClientID",
			cfg: Config{
				Kind:         "builtin",
				ClientSecret: "secret",
				RedirectURI:  "http://localhost:8080/callback",
			},
			wantErr: true,
		},
		{
			name: "builtin missing ClientSecret",
			cfg: Config{
				Kind:        "builtin",
				ClientID:    "cid",
				RedirectURI: "http://localhost:8080/callback",
			},
			wantErr: true,
		},
		{
			name: "builtin missing RedirectURI",
			cfg: Config{
				Kind:         "builtin",
				ClientID:     "cid",
				ClientSecret: "secret",
			},
			wantErr: true,
		},
		{
			name: "builtin invalid RedirectURI scheme",
			cfg: Config{
				Kind:         "builtin",
				ClientID:     "cid",
				ClientSecret: "secret",
				RedirectURI:  "ftp://localhost:8080/callback",
			},
			wantErr: true,
		},
		{
			name: "builtin default scopes applied when Scopes empty",
			cfg: Config{
				Kind:         "builtin",
				ClientID:     "cid",
				ClientSecret: "secret",
				RedirectURI:  "http://localhost:8080/callback",
			},
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := New(tc.cfg)
			if tc.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if p.Name() != "builtin" {
				t.Errorf("Name(): got %q, want %q", p.Name(), "builtin")
			}
		})
	}
}

func TestNewBuiltinDefaultScopes(t *testing.T) {
	p, err := New(Config{
		Kind:         "builtin",
		ClientID:     "cid",
		ClientSecret: "secret",
		RedirectURI:  "http://localhost:8080/callback",
		// Scopes intentionally omitted
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := p.Scopes(); got != "read:user,user:email" {
		t.Errorf("default Scopes: got %q, want %q", got, "read:user,user:email")
	}
}
