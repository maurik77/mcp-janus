package oauth
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"mcpproxy/internal/config"
)

var (
	// ErrDiscoveryFailed indicates OAuth discovery failed
	ErrDiscoveryFailed = errors.New("OAuth discovery failed")
	// ErrTokenExchangeFailed indicates token exchange failed
	ErrTokenExchangeFailed = errors.New("token exchange failed")
)

// OAuthProvider handles OAuth 2.1 flows with upstream authorization servers
type OAuthProvider interface {
	// DiscoverAuthorizationServer fetches RFC 8414 metadata
	DiscoverAuthorizationServer(ctx context.Context, resourceURL string) (*AuthServerMetadata, error)

	// RegisterClient performs dynamic client registration (RFC 7591)
	RegisterClient(ctx context.Context, registrationEndpoint string, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error)

	// BuildAuthorizationURL creates the authorization URL with PKCE
	BuildAuthorizationURL(req *AuthorizationRequest) (string, error)

	// ExchangeCode exchanges authorization code for tokens
	ExchangeCode(ctx context.Context, req *TokenExchangeRequest) (*TokenResponse, error)

	// RefreshToken refreshes an access token
	RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenResponse, error)
}

// AuthServerMetadata represents RFC 8414 metadata
type AuthServerMetadata struct {
	Issuer                        string   `json:"issuer"`
	AuthorizationEndpoint         string   `json:"authorization_endpoint"`
	TokenEndpoint                 string   `json:"token_endpoint"`
	RegistrationEndpoint          string   `json:"registration_endpoint,omitempty"`
	JwksURI                       string   `json:"jwks_uri,omitempty"`
	ResponseTypesSupported        []string `json:"response_types_supported"`
	GrantTypesSupported           []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`
}

// AuthorizationRequest for building authorization URL
type AuthorizationRequest struct {
	AuthorizationEndpoint string
	ClientID              string
	RedirectURI           string
	State                 string
	CodeChallenge         string
	CodeChallengeMethod   string // "S256"
	Scope                 string
	Resource              string // RFC 8707
}

// TokenExchangeRequest for exchanging code
type TokenExchangeRequest struct {
	TokenEndpoint string
	Code          string
	CodeVerifier  string
	ClientID      string
	ClientSecret  string // optional for public clients
	RedirectURI   string
	Resource      string // RFC 8707
}

// TokenResponse from authorization server
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// RefreshTokenRequest for token refresh
type RefreshTokenRequest struct {
	TokenEndpoint string
	RefreshToken  string
	ClientID      string
	ClientSecret  string
	Scope         string
}

// ClientRegistrationRequest for RFC 7591
type ClientRegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	ClientName              string   `json:"client_name"`
	ClientURI               string   `json:"client_uri,omitempty"`
}

// ClientRegistrationResponse from RFC 7591
type ClientRegistrationResponse struct {
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at,omitempty"`
}

// oauthProviderImpl implements OAuthProvider
type oauthProviderImpl struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewProvider creates a new OAuth provider
func NewProvider(cfg *config.Config) OAuthProvider {
	return &oauthProviderImpl{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// DiscoverAuthorizationServer fetches RFC 8414 metadata
func (p *oauthProviderImpl) DiscoverAuthorizationServer(ctx context.Context, resourceURL string) (*AuthServerMetadata, error) {
	// First, get protected resource metadata (RFC 9728)
	// This would typically be at /.well-known/oauth-protected-resource
	parsedURL, err := url.Parse(resourceURL)
	if err != nil {
		return nil, fmt.Errorf("invalid resource URL: %w", err)
	}

	discoveryURL := fmt.Sprintf("%s://%s/.well-known/oauth-authorization-server", parsedURL.Scheme, parsedURL.Host)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	var metadata AuthServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}

// RegisterClient performs dynamic client registration (RFC 7591)
func (p *oauthProviderImpl) RegisterClient(ctx context.Context, registrationEndpoint string, req *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, registrationEndpoint, strings.NewReader(string(body)))
	if err != nil {
		return nil, fmt.Errorf("failed to create registration request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("registration request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registration failed with status %d", resp.StatusCode)
	}

	var regResp ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&regResp); err != nil {
		return nil, fmt.Errorf("failed to decode registration response: %w", err)
	}

	return &regResp, nil
}

// BuildAuthorizationURL creates the authorization URL with PKCE
func (p *oauthProviderImpl) BuildAuthorizationURL(req *AuthorizationRequest) (string, error) {
	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("state", req.State)
	params.Set("code_challenge", req.CodeChallenge)
	params.Set("code_challenge_method", req.CodeChallengeMethod)

	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}

	if req.Resource != "" {
		params.Set("resource", req.Resource)
	}

	authURL := fmt.Sprintf("%s?%s", req.AuthorizationEndpoint, params.Encode())
	return authURL, nil
}

// ExchangeCode exchanges authorization code for tokens
func (p *oauthProviderImpl) ExchangeCode(ctx context.Context, req *TokenExchangeRequest) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", req.Code)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("client_id", req.ClientID)
	params.Set("code_verifier", req.CodeVerifier)

	if req.ClientSecret != "" {
		params.Set("client_secret", req.ClientSecret)
	}

	if req.Resource != "" {
		params.Set("resource", req.Resource)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: status %d, body: %s", ErrTokenExchangeFailed, resp.StatusCode, string(bodyBytes))
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode token response: %w", err)
	}

	return &tokenResp, nil
}

// RefreshToken refreshes an access token
func (p *oauthProviderImpl) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*TokenResponse, error) {
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", req.RefreshToken)
	params.Set("client_id", req.ClientID)

	if req.ClientSecret != "" {
		params.Set("client_secret", req.ClientSecret)
	}

	if req.Scope != "" {
		params.Set("scope", req.Scope)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, req.TokenEndpoint, strings.NewReader(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := p.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode refresh response: %w", err)
	}

	return &tokenResp, nil
}

// GeneratePKCEChallenge generates a PKCE code verifier and challenge
func GeneratePKCEChallenge() (verifier, challenge string, err error) {
	// Generate code verifier (43-128 characters)
	verifierBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, verifierBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate verifier: %w", err)
	}

	verifier = base64.URLEncoding.EncodeToString(verifierBytes)
	verifier = strings.TrimRight(verifier, "=")

	// Generate code challenge (S256)
	hash := sha256.Sum256([]byte(verifier))
	challenge = base64.URLEncoding.EncodeToString(hash[:])
	challenge = strings.TrimRight(challenge, "=")

	return verifier, challenge, nil
}

// GenerateState generates a random state parameter
func GenerateState() (string, error) {
	stateBytes := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, stateBytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}

	state := base64.URLEncoding.EncodeToString(stateBytes)
	state = strings.TrimRight(state, "=")
	return state, nil
}
