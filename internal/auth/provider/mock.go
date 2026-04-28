package provider

import (
	"context"
	"net/url"
)

// Mock is an in-memory Provider implementation for tests.
//
// Field-level overrides drive per-method behavior without requiring a fake
// HTTP server.
type Mock struct {
	NameValue        string
	ClientIDValue    string
	ScopesValue      string
	AuthorizeURLFunc func(state, codeChallenge string) string
	ExchangeCodeFunc func(ctx context.Context, code string) (string, []string, error)
	ValidateFunc     func(ctx context.Context, token string) (Identity, error)
}

func (m *Mock) Name() string {
	if m.NameValue == "" {
		return "mock"
	}
	return m.NameValue
}

func (m *Mock) ClientID() string { return m.ClientIDValue }
func (m *Mock) Scopes() string   { return m.ScopesValue }

func (m *Mock) AuthorizeURL(state, codeChallenge string) string {
	if m.AuthorizeURLFunc != nil {
		return m.AuthorizeURLFunc(state, codeChallenge)
	}
	q := url.Values{}
	q.Set("state", state)
	return "https://mock.example.com/authorize?" + q.Encode()
}

func (m *Mock) ExchangeCode(ctx context.Context, code string) (string, []string, error) {
	if m.ExchangeCodeFunc != nil {
		return m.ExchangeCodeFunc(ctx, code)
	}
	return "mock-token-for-" + code, []string{"mock"}, nil
}

func (m *Mock) ValidateToken(ctx context.Context, token string) (Identity, error) {
	if m.ValidateFunc != nil {
		return m.ValidateFunc(ctx, token)
	}
	return Identity{Provider: m.Name(), Subject: "mock-user"}, nil
}
