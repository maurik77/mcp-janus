package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
)

var (
	// ErrClientNotFound indicates client not found
	ErrClientNotFound = errors.New("client not found")
	// ErrInvalidClientMetadata indicates invalid client metadata
	ErrInvalidClientMetadata = errors.New("invalid client metadata")
)

// LocalClientRegistry implements in-memory dynamic client registration
// without calling external IDP (RFC 7591 compliant)
type LocalClientRegistry interface {
	// RegisterClient registers a new OAuth client locally
	RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error)

	// GetClient retrieves client information by client_id
	GetClient(ctx context.Context, clientID string) (*RegisteredClient, error)

	// DeleteClient removes a registered client
	DeleteClient(ctx context.Context, clientID string) error

	// ValidateClient checks client credentials
	ValidateClient(ctx context.Context, clientID, clientSecret string) error
}

// RegisteredClient stores registered client information
type RegisteredClient struct {
	ClientID                string
	ClientSecret            string
	ClientIDIssuedAt        int64
	ClientSecretExpiresAt   int64
	RedirectURIs            []string
	TokenEndpointAuthMethod string
	GrantTypes              []string
	ResponseTypes           []string
	ClientName              string
	ClientURI               string
}

// localClientRegistryImpl implements LocalClientRegistry
type localClientRegistryImpl struct {
	clients map[string]*RegisteredClient
	mu      sync.RWMutex
}

// NewLocalClientRegistry creates a new local client registry
func NewLocalClientRegistry() LocalClientRegistry {
	return &localClientRegistryImpl{
		clients: make(map[string]*RegisteredClient),
	}
}

// RegisterClient registers a new OAuth client locally
func (r *localClientRegistryImpl) RegisterClient(ctx context.Context, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	// Validate registration request
	if err := validateClientRegistrationRequest(req); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidClientMetadata, err)
	}

	// Generate client ID
	clientID, err := generateClientID()
	if err != nil {
		return nil, fmt.Errorf("failed to generate client ID: %w", err)
	}

	// Generate client secret for confidential clients
	var clientSecret string
	var secretExpiresAt int64

	if req.TokenEndpointAuthMethod != "none" {
		clientSecret, err = generateClientSecret()
		if err != nil {
			return nil, fmt.Errorf("failed to generate client secret: %w", err)
		}
		// Set expiry to 0 (does not expire) or a future date
		secretExpiresAt = 0
	}

	issuedAt := time.Now().Unix()

	// Store client
	client := &RegisteredClient{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        issuedAt,
		ClientSecretExpiresAt:   secretExpiresAt,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
	}

	r.clients[clientID] = client

	// Return registration response
	return &ClientRegistrationResponse{
		ClientID:              clientID,
		ClientSecret:          clientSecret,
		ClientIDIssuedAt:      issuedAt,
		ClientSecretExpiresAt: secretExpiresAt,
	}, nil
}

// GetClient retrieves client information by client_id
func (r *localClientRegistryImpl) GetClient(ctx context.Context, clientID string) (*RegisteredClient, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	client, ok := r.clients[clientID]
	if !ok {
		return nil, ErrClientNotFound
	}

	// Return a copy to prevent external modification
	clientCopy := *client
	return &clientCopy, nil
}

// DeleteClient removes a registered client
func (r *localClientRegistryImpl) DeleteClient(ctx context.Context, clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, ok := r.clients[clientID]; !ok {
		return ErrClientNotFound
	}

	delete(r.clients, clientID)
	return nil
}

// ValidateClient checks client credentials
func (r *localClientRegistryImpl) ValidateClient(ctx context.Context, clientID, clientSecret string) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	client, ok := r.clients[clientID]
	if !ok {
		return ErrClientNotFound
	}

	// For public clients (token_endpoint_auth_method = "none"), no secret is required
	if client.TokenEndpointAuthMethod == "none" {
		return nil
	}

	// Validate secret for confidential clients
	if client.ClientSecret != clientSecret {
		return errors.New("invalid client secret")
	}

	// Check if secret is expired
	if client.ClientSecretExpiresAt > 0 && time.Now().Unix() > client.ClientSecretExpiresAt {
		return errors.New("client secret expired")
	}

	return nil
}

// validateClientRegistrationRequest validates RFC 7591 registration request
func validateClientRegistrationRequest(req *ClientRegistrationRequest) error {
	if len(req.RedirectURIs) == 0 {
		return errors.New("redirect_uris is required")
	}

	// Validate redirect URIs
	for _, uri := range req.RedirectURIs {
		if uri == "" {
			return errors.New("redirect_uri cannot be empty")
		}
		// In production, validate URI format and scheme
	}

	// Set defaults
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}

	if len(req.GrantTypes) == 0 {
		req.GrantTypes = []string{"authorization_code"}
	}

	if len(req.ResponseTypes) == 0 {
		req.ResponseTypes = []string{"code"}
	}

	// Validate token_endpoint_auth_method
	validAuthMethods := []string{"client_secret_basic", "client_secret_post", "none"}
	validMethod := false
	for _, method := range validAuthMethods {
		if req.TokenEndpointAuthMethod == method {
			validMethod = true
			break
		}
	}
	if !validMethod {
		return fmt.Errorf("invalid token_endpoint_auth_method: %s", req.TokenEndpointAuthMethod)
	}

	return nil
}

// generateClientID generates a unique client identifier
func generateClientID() (string, error) {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	clientID := base64.URLEncoding.EncodeToString(b)
	clientID = strings.TrimRight(clientID, "=")
	return "mcp-proxy-" + clientID, nil
}

// generateClientSecret generates a secure client secret
func generateClientSecret() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	secret := base64.URLEncoding.EncodeToString(b)
	secret = strings.TrimRight(secret, "=")
	return secret, nil
}
