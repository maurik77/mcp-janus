# MCP Proxy Server - Design Document

## 1. Component Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         MCP Client                               │
│                                                                   │
│  - Initiates OAuth flow                                          │
│  - Receives opaque bearer token                                  │
│  - Makes MCP requests with token                                 │
└────────────────┬────────────────────────────────────────────────┘
                 │
                 │ 1. Authorization request
                 │ 2. Opaque bearer token
                 │ 3. MCP requests (with opaque token)
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│                    MCP Proxy Server (This Project)               │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │  HTTP Server (pkg/http)                                 │    │
│  │  - /auth/authorize  (OAuth initiation)                  │    │
│  │  - /auth/callback   (OAuth callback)                    │    │
│  │  - /token           (Opaque token issuance)             │    │
│  │  - /.well-known/oauth-protected-resource (RFC 9728)     │    │
│  │  - /mcp/*           (MCP forwarding layer)              │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│  ┌────────────────────────┼──────────────────────────────┐      │
│  │  internal/oauth        │  internal/tokens             │      │
│  │  - OAuthProvider       │  - TokenStore                │      │
│  │  - Discovery           │  - OpaqueTokenService        │      │
│  │  - PKCE                │  - Validation                │      │
│  └────────────────────────┴──────────────────────────────┘      │
│                           │                                      │
│  ┌────────────────────────┼──────────────────────────────┐      │
│  │  internal/crypto       │  internal/mcp                │      │
│  │  - CryptoService       │  - MCPClient                 │      │
│  │  - AEAD (AES-GCM)      │  - Forwarding                │      │
│  │  - Key rotation        │  - Upstream token injection  │      │
│  └────────────────────────┴──────────────────────────────┘      │
│                           │                                      │
│  ┌────────────────────────────────────────────────────────┐     │
│  │  internal/config                                        │     │
│  │  - Environment configuration                            │     │
│  │  - Validation                                           │     │
│  └────────────────────────────────────────────────────────┘     │
└────────────────┬────────────────┬───────────────────────────────┘
                 │                │
                 │                │ 4. Upstream MCP requests
                 │                │    (with upstream token)
                 │                ▼
                 │   ┌────────────────────────────┐
                 │   │   Protected MCP Server      │
                 │   │   (Upstream Resource)       │
                 │   └────────────────────────────┘
                 │
                 │ OAuth flow (for upstream token)
                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Upstream Authorization Server                       │
│                                                                   │
│  - Issues tokens for upstream MCP server                         │
│  - OAuth 2.1 compliant                                           │
│  - Supports PKCE, Dynamic Registration                           │
└─────────────────────────────────────────────────────────────────┘
```

## 2. OAuth Flow Sequences

### 2.1 Authorization Code Flow (Client ↔ Proxy)

```
MCP Client         Proxy Server        Upstream AS        Upstream MCP
    │                   │                    │                  │
    │  1. GET /mcp      │                    │                  │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │  2. 401 + WWW-Authenticate             │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  3. GET /.well-known/oauth-protected-resource             │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │  4. Resource Metadata                  │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  5. POST /auth/authorize               │                  │
    │     (code_challenge, state)            │                  │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │  6. 302 Redirect to user browser       │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  [User authenticates with Proxy]       │                  │
    │                   │                    │                  │
    │  7. Proxy initiates upstream OAuth     │                  │
    │                   │ ──────────────────>│                  │
    │                   │  (PKCE, resource)  │                  │
    │                   │                    │                  │
    │                   │  8. Auth Code      │                  │
    │                   │ <──────────────────│                  │
    │                   │                    │                  │
    │  9. 302 Redirect to /auth/callback     │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  10. GET /auth/callback                │                  │
    │      (code, state)│                    │                  │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │                   │ 11. POST /token    │                  │
    │                   │     (code_verifier)│                  │
    │                   │ ──────────────────>│                  │
    │                   │                    │                  │
    │                   │ 12. Upstream token │                  │
    │                   │ <──────────────────│                  │
    │                   │                    │                  │
    │                   │ [Store: rtid → upstream creds]        │
    │                   │                    │                  │
    │  13. 302 with auth code                │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  14. POST /token  │                    │                  │
    │      (code, code_verifier)             │                  │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │                   │ [Generate opaque token with rtid]     │
    │                   │                    │                  │
    │  15. Opaque token │                    │                  │
    │ <──────────────   │                    │                  │
    │                   │                    │                  │
    │  16. GET /mcp     │                    │                  │
    │      (Authorization: Bearer <opaque>)  │                  │
    │ ──────────────>   │                    │                  │
    │                   │                    │                  │
    │                   │ [Decrypt opaque token, get rtid]      │
    │                   │ [Retrieve upstream creds]             │
    │                   │                    │                  │
    │                   │ 17. GET /mcp       │                  │
    │                   │     (Authorization: Bearer <upstream>)│
    │                   │ ───────────────────────────────────────>
    │                   │                    │                  │
    │                   │ 18. MCP Response   │                  │
    │                   │ <───────────────────────────────────────
    │                   │                    │                  │
    │  19. MCP Response │                    │                  │
    │ <──────────────   │                    │                  │
```

### 2.2 Opaque Token Structure

The proxy issues its **own opaque bearer token** to the MCP client. This token is encrypted (AEAD) and is NOT a passthrough.

**Plaintext Payload (before encryption):**
```json
{
  "rtid": "uuid-v4-reference-to-upstream-credentials",
  "exp": 1698765432,
  "aud": "https://proxy.example.com",
  "scp": "mcp:read mcp:write",
  "ver": 1,
  "kid": "key-id-for-rotation"
}
```

**Encrypted Format:**
```
<base64url(encrypted_payload)>.<base64url(nonce)>.<base64url(tag)>
```

**Encryption:** AES-256-GCM or XChaCha20-Poly1305

## 3. Go Interface Definitions

### 3.1 internal/oauth/provider.go

```go
package oauth

import (
    "context"
    "net/url"
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
    Issuer                            string   `json:"issuer"`
    AuthorizationEndpoint             string   `json:"authorization_endpoint"`
    TokenEndpoint                     string   `json:"token_endpoint"`
    RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
    JwksURI                           string   `json:"jwks_uri,omitempty"`
    ResponseTypesSupported            []string `json:"response_types_supported"`
    GrantTypesSupported               []string `json:"grant_types_supported"`
    CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
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
    ClientID     string `json:"client_id"`
    ClientSecret string `json:"client_secret,omitempty"`
    ClientIDIssuedAt int64 `json:"client_id_issued_at"`
    ClientSecretExpiresAt int64 `json:"client_secret_expires_at,omitempty"`
}
```

### 3.2 internal/tokens/store.go

```go
package tokens

import (
    "context"
    "time"
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
```

### 3.3 internal/tokens/opaque.go

```go
package tokens

import (
    "context"
    "time"
)

// OpaqueTokenService creates and validates opaque bearer tokens
type OpaqueTokenService interface {
    // Create generates an opaque token from payload
    Create(ctx context.Context, payload *OpaqueTokenPayload) (string, error)
    
    // Validate decrypts and validates an opaque token
    Validate(ctx context.Context, token string) (*OpaqueTokenPayload, error)
}

// OpaqueTokenPayload is the plaintext content before encryption
type OpaqueTokenPayload struct {
    RTID     string   `json:"rtid"`      // Reference to upstream credentials
    Exp      int64    `json:"exp"`       // Expiry timestamp
    Aud      string   `json:"aud"`       // Audience (this proxy URL)
    Scope    []string `json:"scp"`       // Scopes
    Ver      int      `json:"ver"`       // Token format version
    KID      string   `json:"kid"`       // Key ID for rotation
}

// IsExpired checks if token is expired
func (p *OpaqueTokenPayload) IsExpired() bool {
    return time.Now().Unix() > p.Exp
}
```

### 3.4 internal/crypto/service.go

```go
package crypto

import (
    "context"
)

// CryptoService handles AEAD encryption/decryption and key management
type CryptoService interface {
    // Encrypt encrypts plaintext using AEAD (AES-GCM or XChaCha20-Poly1305)
    Encrypt(ctx context.Context, plaintext []byte, kid string) (ciphertext, nonce, tag []byte, err error)
    
    // Decrypt decrypts ciphertext using AEAD
    Decrypt(ctx context.Context, ciphertext, nonce, tag []byte, kid string) ([]byte, error)
    
    // GetCurrentKeyID returns the current active key ID
    GetCurrentKeyID(ctx context.Context) string
    
    // RotateKeys generates new encryption key and updates KID
    RotateKeys(ctx context.Context) error
    
    // GetKey retrieves key by KID (for decryption of old tokens)
    GetKey(ctx context.Context, kid string) ([]byte, error)
}

// KeyStore manages encryption keys
type KeyStore interface {
    // GetKey retrieves a key by ID
    GetKey(ctx context.Context, kid string) ([]byte, error)
    
    // StoreKey stores a new key
    StoreKey(ctx context.Context, kid string, key []byte) error
    
    // ListKeys returns all key IDs
    ListKeys(ctx context.Context) ([]string, error)
    
    // GetCurrentKID returns the active key ID
    GetCurrentKID(ctx context.Context) (string, error)
    
    // SetCurrentKID sets the active key ID
    SetCurrentKID(ctx context.Context, kid string) error
}
```

### 3.5 internal/mcp/client.go

```go
package mcp

import (
    "context"
    "net/http"
)

// MCPClient forwards validated requests to upstream MCP server
type MCPClient interface {
    // Forward proxies an MCP request to the upstream server
    Forward(ctx context.Context, req *ProxyRequest) (*ProxyResponse, error)
    
    // DiscoverServer performs RFC 9728 discovery
    DiscoverServer(ctx context.Context, serverURL string) (*ProtectedResourceMetadata, error)
}

// ProxyRequest represents a validated request to be forwarded
type ProxyRequest struct {
    Method          string
    Path            string
    Headers         http.Header
    Body            []byte
    UpstreamToken   string // Token for upstream server
    UpstreamURL     string // Target MCP server URL
}

// ProxyResponse from upstream server
type ProxyResponse struct {
    StatusCode int
    Headers    http.Header
    Body       []byte
}

// ProtectedResourceMetadata from RFC 9728
type ProtectedResourceMetadata struct {
    Resource              string   `json:"resource"`
    AuthorizationServers  []string `json:"authorization_servers"`
    BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
    ResourceDocumentation string   `json:"resource_documentation,omitempty"`
}
```

### 3.6 internal/config/config.go

```go
package config

import (
    "time"
)

// Config holds all configuration for the proxy
type Config struct {
    // Server config
    ListenAddr      string        // :8080
    TLSCertFile     string        // path to cert
    TLSKeyFile      string        // path to key
    ShutdownTimeout time.Duration // 30s
    
    // Proxy identity
    ProxyURL        string        // https://proxy.example.com
    
    // Upstream MCP server
    UpstreamMCPURL  string        // https://mcp.example.com
    
    // Token settings
    OpaqueTokenTTL  time.Duration // 15 minutes
    
    // Crypto settings
    KeyStoreType    string        // "memory", "file", "kms"
    KeyStorePath    string        // path for file-based keys
    
    // Rate limiting
    RateLimitEnabled bool
    RateLimitRPS     int
    RateLimitBurst   int
    
    // Logging
    LogLevel        string        // "info", "debug", "error"
    LogFormat       string        // "json", "text"
}

// Validate checks configuration
func (c *Config) Validate() error {
    // Implementation
    return nil
}

// LoadFromEnv loads config from environment variables
func LoadFromEnv() (*Config, error) {
    // Implementation
    return nil, nil
}
```

## 4. HTTP Endpoints

### 4.1 Proxy Endpoints (Acting as OAuth Resource Server)

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 Protected Resource Metadata |
| `/auth/authorize` | POST | Initiate OAuth flow (proxy acts as client to upstream) |
| `/auth/callback` | GET | OAuth callback handler |
| `/token` | POST | Issue opaque bearer token to MCP client |
| `/mcp/*` | ALL | Forward MCP requests to upstream server |

### 4.2 Protected Resource Metadata (RFC 9728)

**GET** `/.well-known/oauth-protected-resource`

Response:
```json
{
  "resource": "https://proxy.example.com",
  "authorization_servers": [
    "https://proxy.example.com/auth"
  ],
  "bearer_methods_supported": ["header"],
  "resource_documentation": "https://proxy.example.com/docs"
}
```

### 4.3 Token Endpoint

**POST** `/token`

Request (Authorization Code):
```
grant_type=authorization_code
&code=<authorization_code>
&redirect_uri=<redirect_uri>
&client_id=<client_id>
&code_verifier=<pkce_verifier>
```

Request (Refresh Token):
```
grant_type=refresh_token
&refresh_token=<refresh_token>
&client_id=<client_id>
```

Response:
```json
{
  "access_token": "<opaque_token>",
  "token_type": "Bearer",
  "expires_in": 900,
  "refresh_token": "<refresh_token>",
  "scope": "mcp:read mcp:write"
}
```

## 5. Middleware Stack

```
Request
  │
  ├─> Logging Middleware (request ID, no secrets)
  │
  ├─> HTTPS Enforcement (redirect HTTP → HTTPS, except localhost)
  │
  ├─> Rate Limiting (per client IP or client ID)
  │
  ├─> CORS Headers (if needed)
  │
  ├─> Authentication Middleware
  │    ├─> Extract Authorization header
  │    ├─> Validate opaque token (decrypt, check exp, aud)
  │    ├─> Retrieve upstream credentials by rtid
  │    └─> Add to context
  │
  ├─> Authorization Middleware
  │    ├─> Check scopes
  │    └─> Validate resource access
  │
  └─> Handler (forward to upstream MCP or handle OAuth endpoint)
```

## 6. Key Security Patterns

### 6.1 No Token Passthrough
- Proxy **never** forwards client tokens to upstream
- Proxy obtains its own upstream tokens
- Client receives opaque tokens issued by proxy

### 6.2 Audience Validation
- Proxy validates opaque token audience matches proxy URL
- Proxy includes `resource` parameter when requesting upstream tokens
- Upstream tokens bound to upstream MCP server

### 6.3 Key Rotation
- Keys identified by KID
- Old keys retained for decryption
- New tokens use current KID
- Rotation script provided

### 6.4 Short-lived Tokens
- Opaque access tokens: 15 minutes (configurable)
- Refresh tokens: rotate on each use
- Upstream tokens: per upstream AS policy

### 6.5 Secure Storage
- Keys: OS keychain, KMS, or encrypted file
- Upstream credentials: encrypted at rest
- No secrets in logs

## 7. Error Handling Strategy

### 7.1 OAuth Errors
```go
type OAuthError struct {
    Error            string `json:"error"`
    ErrorDescription string `json:"error_description,omitempty"`
    ErrorURI         string `json:"error_uri,omitempty"`
}
```

### 7.2 HTTP Status Codes
- 400: Malformed request
- 401: Invalid or expired token
- 403: Insufficient permissions
- 500: Internal error
- 502: Upstream error
- 503: Service unavailable

### 7.3 Error Wrapping
```go
// Use Go's error wrapping
return fmt.Errorf("failed to decrypt token: %w", err)

// Check with errors.Is
if errors.Is(err, ErrTokenExpired) {
    // Handle expiry
}
```

## 8. Testing Strategy

### 8.1 Unit Tests
- Crypto: encrypt/decrypt, key rotation
- Token validation: expiry, audience, tampering
- PKCE: verifier/challenge generation
- OAuth URL building

### 8.2 Integration Tests
- Full OAuth flow (mock upstream AS)
- Token issuance and validation
- MCP request forwarding
- Error scenarios

### 8.3 Table-driven Tests
```go
tests := []struct {
    name    string
    input   string
    want    string
    wantErr bool
}{
    {
        name:  "valid token",
        input: "eyJhbG...",
        want:  "rtid-123",
        wantErr: false,
    },
    // ...
}
```

## 9. Logging Guidelines

### 9.1 What to Log
- Request IDs (correlation)
- Client IDs (never client secrets)
- Token RTIDs (never token values)
- Timestamps
- Status codes
- Error types
- Key rotation events

### 9.2 What NOT to Log
- Access tokens (opaque or upstream)
- Refresh tokens
- Client secrets
- Authorization codes
- Code verifiers
- Encryption keys
- User passwords

### 9.3 Structured Logging Example
```go
slog.Info("token issued",
    "request_id", requestID,
    "client_id", clientID,
    "rtid", rtid,
    "expires_in", expiresIn,
)
```

## 10. Deployment Considerations

### 10.1 Environment Variables
```bash
PROXY_LISTEN_ADDR=:8443
PROXY_TLS_CERT=/path/to/cert.pem
PROXY_TLS_KEY=/path/to/key.pem
PROXY_URL=https://proxy.example.com
UPSTREAM_MCP_URL=https://mcp.example.com
OPAQUE_TOKEN_TTL=15m
KEY_STORE_TYPE=kms
RATE_LIMIT_RPS=100
LOG_LEVEL=info
```

### 10.2 Health Check Endpoint
```
GET /health → 200 OK
```

### 10.3 Metrics (optional)
- Requests per second
- Token issuance rate
- Token validation failures
- Upstream latency
- Error rates

---

## Summary

This design provides:
1. ✅ OAuth 2.1 compliance with PKCE
2. ✅ Opaque bearer token issuance (no passthrough)
3. ✅ AEAD encryption for tokens
4. ✅ Audience binding and validation
5. ✅ Key rotation support
6. ✅ Idiomatic Go interfaces
7. ✅ Clear separation of concerns
8. ✅ Security-first architecture
9. ✅ Testable components
10. ✅ Comprehensive logging (no secrets)
