package tokens
package tokens

import (
	"context"
	"errors"
	"sync"
	"time"

	"mcpproxy/internal/config"
)

var (
	// ErrTokenNotFound indicates token not found in store
	ErrTokenNotFound = errors.New("token not found")
	// ErrTokenExpired indicates token has expired
	ErrTokenExpired = errors.New("token expired")
)

// TokenStore manages upstream credentials indexed by rtid
type TokenStore interface {
	// Store saves upstream credentials with a unique rtid
	Store(ctx context.Context, rtid string, creds *UpstreamCredentials) error

	// Retrieve gets upstream credentials by rtid
	Retrieve(ctx context.Context, rtid string) (*UpstreamCredentials, error)

	// Delete removes credentials
	Delete(ctx context.Context, rtid string) error

	// RefreshIfNeeded checks expiry and refreshes if necessary
	RefreshIfNeeded(ctx context.Context, rtid string) (*UpstreamCredentials, error)
}

// UpstreamCredentials stored by rtid
type UpstreamCredentials struct {
	RTID         string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
	Scope        string
	ResourceURL  string // Which upstream MCP server this is for
}

// IsExpired checks if the credentials are expired
func (c *UpstreamCredentials) IsExpired() bool {
	// Add 1-minute buffer for clock skew
	return time.Now().Add(1 * time.Minute).After(c.ExpiresAt)
}

// MemoryStore is an in-memory implementation of TokenStore
type MemoryStore struct {
	credentials map[string]*UpstreamCredentials
	cfg         *config.Config
	mu          sync.RWMutex
}

// NewMemoryStore creates a new in-memory token store
func NewMemoryStore(cfg *config.Config) (*MemoryStore, error) {
	return &MemoryStore{
		credentials: make(map[string]*UpstreamCredentials),
		cfg:         cfg,
	}, nil
}

// Store saves upstream credentials
func (s *MemoryStore) Store(ctx context.Context, rtid string, creds *UpstreamCredentials) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external modification
	credsCopy := *creds
	s.credentials[rtid] = &credsCopy
	return nil
}

// Retrieve gets upstream credentials by rtid
func (s *MemoryStore) Retrieve(ctx context.Context, rtid string) (*UpstreamCredentials, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	creds, ok := s.credentials[rtid]
	if !ok {
		return nil, ErrTokenNotFound
	}

	// Return a copy to prevent external modification
	credsCopy := *creds
	return &credsCopy, nil
}

// Delete removes credentials
func (s *MemoryStore) Delete(ctx context.Context, rtid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.credentials, rtid)
	return nil
}

// RefreshIfNeeded checks expiry and refreshes if necessary
func (s *MemoryStore) RefreshIfNeeded(ctx context.Context, rtid string) (*UpstreamCredentials, error) {
	creds, err := s.Retrieve(ctx, rtid)
	if err != nil {
		return nil, err
	}

	if !creds.IsExpired() {
		return creds, nil
	}

	// Token is expired but refresh logic is handled by OAuth provider
	// This is a placeholder - actual refresh would involve calling OAuthProvider.RefreshToken
	return nil, ErrTokenExpired
}
