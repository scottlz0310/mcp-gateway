// Package githubapp provides short-lived GitHub App installation credentials
// for server-to-server upstream routes.
package githubapp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAPIBaseURL = "https://api.github.com"
	apiVersion        = "2026-03-10"
	refreshLeeway     = 5 * time.Minute
	maxResponseBytes  = 1 << 20
)

// Config contains the GitHub App installation identity. PrivateKeyPEM is
// expected to have already been decrypted by the config package.
type Config struct {
	ClientID       string
	InstallationID int64
	PrivateKeyPEM  string
	APIBaseURL     string
	HTTPClient     *http.Client
	Now            func() time.Time
}

// Status is a secret-free snapshot for operational diagnostics.
type Status struct {
	CredentialType string
	InstallationID int64
	ExpiresAt      time.Time
	Ready          bool
}

// TokenSource caches and refreshes a GitHub App installation token. The mutex
// intentionally spans the network request so concurrent callers cannot mint a
// burst of redundant tokens.
type TokenSource struct {
	clientID       string
	installationID int64
	privateKey     *rsa.PrivateKey
	apiBaseURL     string
	httpClient     *http.Client
	now            func() time.Time

	mu        sync.Mutex
	token     string
	expiresAt time.Time
}

// NewTokenSource validates the installation configuration and private key.
func NewTokenSource(cfg Config) (*TokenSource, error) {
	clientID := strings.TrimSpace(cfg.ClientID)
	if clientID == "" {
		return nil, errors.New("github app client ID must not be empty")
	}
	if cfg.InstallationID <= 0 {
		return nil, errors.New("github app installation ID must be positive")
	}
	privateKey, err := parsePrivateKey([]byte(cfg.PrivateKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parsing GitHub App private key: %w", err)
	}
	baseURL := strings.TrimRight(strings.TrimSpace(cfg.APIBaseURL), "/")
	if baseURL == "" {
		baseURL = defaultAPIBaseURL
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Scheme == "" || parsedBase.Host == "" || (parsedBase.Scheme != "http" && parsedBase.Scheme != "https") {
		return nil, fmt.Errorf("GitHub API base URL must be an absolute HTTP(S) URL")
	}
	httpClient := cfg.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	return &TokenSource{
		clientID:       clientID,
		installationID: cfg.InstallationID,
		privateKey:     privateKey,
		apiBaseURL:     baseURL,
		httpClient:     httpClient,
		now:            now,
	}, nil
}

// Token returns a cached token or mints a new token before the proactive
// refresh window. Raw credentials are never included in returned errors.
func (s *TokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.expiresAt.After(s.now().Add(refreshLeeway)) {
		return s.token, nil
	}
	return s.issueLocked(ctx)
}

// RefreshAfter401 refreshes only when rejectedToken is still the cached
// generation. A concurrent request that already rotated the token wins.
func (s *TokenSource) RefreshAfter401(ctx context.Context, rejectedToken string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.token != rejectedToken && s.expiresAt.After(s.now()) {
		return s.token, nil
	}
	return s.issueLocked(ctx)
}

// Status returns metadata only; it never mints a token or exposes its value.
func (s *TokenSource) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return Status{
		CredentialType: "github_app_installation",
		InstallationID: s.installationID,
		ExpiresAt:      s.expiresAt,
		Ready:          s.token != "" && s.expiresAt.After(s.now()),
	}
}

func (s *TokenSource) issueLocked(ctx context.Context) (string, error) {
	appJWT, err := s.signAppJWT()
	if err != nil {
		return "", fmt.Errorf("signing GitHub App JWT: %w", err)
	}
	endpoint := s.apiBaseURL + "/app/installations/" + strconv.FormatInt(s.installationID, 10) + "/access_tokens"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("creating GitHub installation token request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+appJWT)
	req.Header.Set("X-GitHub-Api-Version", apiVersion)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting GitHub installation token: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()
	if resp.StatusCode != http.StatusCreated {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return "", fmt.Errorf("GitHub installation token endpoint returned HTTP %d", resp.StatusCode)
	}
	var payload struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBytes))
	if err := dec.Decode(&payload); err != nil {
		return "", fmt.Errorf("decoding GitHub installation token response: %w", err)
	}
	if strings.TrimSpace(payload.Token) == "" || !payload.ExpiresAt.After(s.now()) {
		return "", errors.New("GitHub installation token response contained no usable token")
	}
	s.token = payload.Token
	s.expiresAt = payload.ExpiresAt
	return s.token, nil
}

func (s *TokenSource) signAppJWT() (string, error) {
	now := s.now()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT"})
	if err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iat": now.Add(-time.Minute).Unix(),
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": s.clientID,
	})
	if err != nil {
		return "", err
	}
	unsigned := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

func parsePrivateKey(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("PEM block not found")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key must be PKCS#1 or PKCS#8 PEM")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key must be RSA")
	}
	return key, nil
}
