# MCP Janus Proxy Server

A secure **OAuth 2.1-compliant MCP (Model Context Protocol) Proxy Server** written in Go that sits between MCP clients and protected MCP servers, managing all communication with robust security controls.

## 🏛️ Why Janus?

**Janus**, the ancient Roman god of doors, gates, transitions, and passages, stands eternal with two faces—one gazing into the past, the other into the future. Guardian of thresholds and beginnings, Janus watches over all that enters and exits, presiding over change and duality.

This proxy embodies the spirit of Janus:

- **🚪 Guardian of Gateways**: Like Janus at the threshold, this proxy stands watch between client and server, controlling passage with unwavering vigilance
- **👁️ Two-Faced Vision**: One face validates incoming requests from clients, the other secures communication with upstream servers—seeing both worlds simultaneously
- **🔄 Master of Transitions**: Transforms client tokens into secure credentials, mediating the passage between trust domains
- **⚖️ Keeper of Boundaries**: Enforces the sacred boundary between public and protected realms, allowing only the worthy to pass
- **🌅 Herald of New Beginnings**: Each request is a new beginning, each token a fresh start, managed with cryptographic ceremony

Just as ancient Romans invoked Janus at the start of any endeavor, this proxy initiates every secure MCP connection, standing as the eternal sentinel at the gateway between worlds.

## 🎯 Project Goal

Implement a secure proxy that:
- ✅ Issues **opaque bearer tokens** to MCP clients (not passthrough)
- ✅ Implements **OAuth 2.0 / OAuth 2.1** flows with PKCE
- ✅ Uses **AEAD encryption** (AES-256-GCM) for token security
- ✅ Enforces **audience binding** and resource validation
- ✅ Supports **key rotation** with KID-based management
- ✅ Provides **structured logging** without exposing secrets

## 📋 Features

### Security

- **No Token Passthrough**: Proxy issues its own opaque tokens, never forwards client tokens
- **AEAD Encryption**: AES-256-GCM for opaque token encryption
- **JWT Integration**: Decrypts opaque tokens to validate JWT claims
- **Claims Mapping**: Configurable mapping of IdP claims to HTTP headers
- **Dynamic Client Registration**: Encrypted client credentials with unique client IDs
- **HTTPS Ready**: Production-ready with TLS support (HTTP for development)

### OAuth 2.1 Compliance

- **Authorization Code + PKCE**: Full support for secure authorization flows
- **Dynamic Client Registration**: RFC 7591 compliant client registration
- **Protected Resource Metadata**: RFC 9728 compliance for resource discovery
- **Token Exchange**: Secure token exchange with upstream IdP
- **Refresh Token Support**: Token refresh endpoint implemented

### Architecture

- **Gin Framework**: High-performance HTTP router with middleware support
- **Modular Services**: Separation of concerns with auth, metadata, and proxy services
- **Configuration-Driven**: YAML-based configuration with environment variable overrides
- **Testable**: Comprehensive test suite with mocks and table-driven tests
- **Production-Ready**: Graceful shutdown, health checks, structured logging

## 🏗️ Architecture

```
┌─────────────┐
│ MCP Client  │ ← Receives opaque bearer token
└──────┬──────┘
       │ Authorization: Bearer <opaque>
       ▼
┌─────────────────────────────────┐
│     MCP Proxy Server (Go)       │
│  ┌──────────────────────────┐   │
│  │ Gin HTTP Router          │   │
│  │ - Auth Service           │   │
│  │ - Metadata Service       │   │
│  │ - Encryption Utility     │   │
│  │ - Config Management      │   │
│  └──────────────────────────┘   │
└──────┬─────────────┬────────────┘
       │             │ Authorization: Bearer <upstream>
       │             ▼
       │    ┌─────────────────┐
       │    │ Protected MCP   │
       │    │ Server          │
       │    └─────────────────┘
       │
       │ OAuth 2.1 flow
       ▼
┌──────────────────────┐
│   Identity Provider  │
│ (Authorization Svr)  │
└──────────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- Go 1.21 or later
- TLS certificates (for production)

### Installation

```bash
git clone <repository-url>
cd mcp-janus
task install
task build
```

### Configuration

Create a `config.yaml` file or set environment variables:

```yaml
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"

idp:
  issuer_url: https://auth.example.com
  client_id: mcp-proxy-client
  client_secret: your-secret-here
  authorization_endpoint: https://auth.example.com/oauth/authorize
  token_endpoint: https://auth.example.com/oauth/token
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email

encryption:
  master_key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

upstream:
  name: my-mcp-server
  resource: https://mcp.example.com
  base_url: https://mcp.example.com
  path_prefix: /mcp
```

Environment variable overrides:

```bash
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_IDP_CLIENT_SECRET="your-secret-here"
```

### Running

```bash
# Development (HTTP) - using Task
task run

# Or run directly with go
go run cmd/proxy/main.go

# Production - build first
task build
./bin/mcpproxy
```

### Health Check

```bash
curl http://localhost:8080/health
# OK
```

## 🧪 Testing with the Test Server

The project includes a test MCP server (`cmd/mcpserver`) that implements a fake weather tool, perfect for testing the proxy without needing real MCP servers.

### Quick Test Setup

```bash
# Build both servers
task build
task build-testserver

# Terminal 1: Start the test MCP server
task run-testserver
# Runs on http://localhost:8081

# Terminal 2: Start the proxy (configure to point to localhost:8081)
task run

# Terminal 3: Run the test script
task test-testserver
```

### Test Server Features

- **Fake Weather Tool**: Returns deterministic weather data for any city and date
- **MCP Protocol**: Implements `tools/list`, `tools/call`, and `initialize` methods
- **No Dependencies**: Runs standalone for easy testing

See [Testing Guide](docs/testing-guide.md) and [Test Server README](cmd/mcpserver/README.md) for details.

## 📖 API Endpoints

### Discovery Endpoints

#### Protected Resource Metadata (RFC 9728)

```http
GET /.well-known/oauth-protected-resource
```

Returns proxy resource metadata with authorization server information.

#### OpenID Configuration

```http
GET /.well-known/openid-configuration
```

Returns OpenID Connect discovery document.

### Dynamic Client Registration

```http
POST /register
Content-Type: application/json

{
  "client_name": "My MCP Client",
  "redirect_uris": ["http://localhost:3000/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"]
}
```

Response: Encrypted client credentials with `client_id` and `client_secret`.

### OAuth Authorization Flow

#### Authorization Endpoint

```http
GET /auth?response_type=code&client_id=<encrypted_id>&redirect_uri=<uri>&state=<state>&code_challenge=<challenge>&code_challenge_method=S256
```

Initiates OAuth authorization with upstream IdP.

#### Callback Endpoint

```http
GET /callback?code=<auth_code>&state=<state>
```

Handles OAuth callback from upstream IdP and returns encrypted authorization code to client.

#### Token Endpoint

```http
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&code=<encrypted_code>&redirect_uri=<uri>&client_id=<encrypted_id>&client_secret=<secret>&code_verifier=<verifier>
```

Response:

```json
{
  "access_token": "<opaque_encrypted_token>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<encrypted_refresh_token>",
  "scope": "openid profile email"
}
```

#### Refresh Token Endpoint

```http
POST /refresh
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token&refresh_token=<encrypted_refresh_token>&client_id=<encrypted_id>&client_secret=<secret>
```

Note: Currently returns 501 Not Implemented.

### MCP Proxy

```http
GET /mcp/*
Authorization: Bearer <opaque_encrypted_token>
```

Forwards authenticated requests to upstream MCP server with decrypted real token.

## 🔐 Security Model

### Opaque Token Flow

1. **Client Registration**: Client registers and receives encrypted `client_id` containing redirect URIs and a generated secret
2. **Authorization**: Client initiates OAuth flow, proxy coordinates with upstream IdP
3. **Token Exchange**: Proxy exchanges authorization code with IdP, receives JWT tokens
4. **Encryption**: Proxy encrypts JWT tokens using AES-256-GCM
5. **Opaque Token**: Client receives encrypted token (opaque to client, contains real JWT)
6. **Request Forwarding**: Proxy decrypts token, validates JWT, injects upstream token into forwarded requests

### Encrypted Client ID Structure

The `client_id` returned during registration is an encrypted payload containing:

- Redirect URIs
- Generated client secret
- Registration metadata

This ensures client credentials are secured and tamper-proof.

### Token Encryption

**Encryption Method**: AES-256-GCM (AEAD)

**Process**:

1. Real JWT token from IdP encrypted with master key
2. Nonce generated for each encryption operation
3. Ciphertext + nonce encoded as base64url
4. Client receives opaque token string

**Decryption & Validation**:

1. Extract bearer token from `Authorization` header
2. Decrypt using master key
3. Parse and validate JWT claims
4. Map claims to HTTP headers per configuration
5. Forward request with real token

### Claims Mapping

The proxy supports mapping IdP JWT claims to HTTP headers for upstream consumption:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

### Key Security Principles

1. **No Token Passthrough**: Client never sees or uses real IdP tokens
2. **Encrypted Storage**: All sensitive tokens encrypted at rest and in transit
3. **JWT Validation**: Full JWT validation before forwarding requests
4. **Configurable Claims**: Flexible claim-to-header mapping
5. **HTTPS Ready**: Production deployment should use TLS
6. **Master Key Security**: Store master key securely (environment variables, secrets manager)

## 🧪 Testing

### Run All Tests

```bash
task test
# or
go test ./... -v
```

### Run Tests with Coverage

```bash
task coverage
# Opens HTML coverage report in browser
```

### Run Specific Package Tests

```bash
go test ./internal/service/auth/... -v
go test ./internal/utility/... -v
go test ./internal/infrastructure/wire/... -v
```

### Integration Testing with Test Server

The project includes a test MCP server for end-to-end testing:

```bash
# Terminal 1: Start test MCP server
task run-testserver

# Terminal 2: Start proxy
task run

# Terminal 3: Run integration tests
task test-testserver
```

See [Testing Guide](docs/testing-guide.md) for detailed testing documentation.

## 📁 Project Structure

```text
mcp-janus/
├── cmd/
│   ├── proxy/
│   │   └── main.go              # Proxy server entry point
│   └── mcpserver/
│       └── main.go              # Test MCP server
├── internal/
│   ├── infrastructure/
│   │   ├── config/
│   │   │   └── config.go        # YAML-based configuration
│   │   └── wire/
│   │       └── gin.go           # Gin router setup & handlers
│   ├── server/
│   │   └── proxy.go             # Auth middleware & proxy logic
│   ├── service/
│   │   ├── auth/
│   │   │   ├── service.go       # Auth service interface
│   │   │   ├── impl.go          # Auth implementation
│   │   │   └── types.go         # Auth request/response types
│   │   └── metadata/
│   │       └── metadata.go      # RFC 9728 & OpenID metadata
│   └── utility/
│       └── encryption.go        # AES-GCM encryption service
├── docs/
│   ├── mcp-auth-notes.md        # MCP spec summary
│   ├── design.md                # Architecture documentation
│   ├── auth-flow.md             # Flow diagrams
│   └── testing-guide.md         # Testing documentation
├── config.yaml                  # Configuration file
├── Taskfile.yaml                # Task runner commands
├── go.mod
├── go.sum
└── README.md                    # This file
```

## 🔧 Development

### Code Style

This project follows idiomatic Go conventions:

- `gofmt` for formatting
- `golangci-lint` for linting (when available)
- Table-driven tests
- Structured error handling
- Clear separation of concerns

### Available Task Commands

View all available commands:

```bash
task --list
```

Key commands:

- `task build` - Build the proxy server
- `task run` - Run the proxy in development mode
- `task test` - Run all tests
- `task coverage` - Generate coverage report
- `task lint` - Run linter (if golangci-lint installed)
- `task fmt` - Format code
- `task build-testserver` - Build test MCP server
- `task run-testserver` - Run test MCP server

### Adding New Features

1. Update configuration in `internal/infrastructure/config/config.go`
2. Define service interfaces in `internal/service/*/service.go`
3. Implement services in `internal/service/*/impl.go`
4. Wire services in `internal/infrastructure/wire/gin.go`
5. Add comprehensive tests with table-driven patterns
6. Update documentation

### Encryption Key Management

Generate a new master key:

```bash
# Generate 32-byte (256-bit) hex key
openssl rand -hex 32
```

Configure in `config.yaml` or via environment variable `MCP_ENCRYPTION_MASTER_KEY`.

## 🛡️ Threat Model

### Protected Against

- ✅ Token passthrough attacks (proxy issues its own tokens)
- ✅ Token tampering (AEAD encryption with authentication)
- ✅ Unauthorized access (OAuth 2.1 with PKCE)
- ✅ Credential exposure (encrypted client IDs and tokens)
- ✅ Man-in-the-middle (HTTPS support for production)
- ✅ Token replay (JWT expiration validation)

### Security Best Practices

- Store master encryption key securely (secrets manager, environment variables)
- Use HTTPS in production
- Rotate encryption keys periodically
- Monitor and log authentication events
- Keep IdP credentials secure
- Regular security audits of dependencies

See documentation in `docs/` for detailed security information.

## 📚 References

### MCP Specifications

- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### OAuth Standards

- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 8414: OAuth 2.0 Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 7591: OAuth 2.0 Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 9728: OAuth 2.0 Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [RFC 8707: Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)

## 🤝 Contributing

1. Follow Go best practices and project conventions
2. Use `task fmt` to format code before committing
3. Add tests for all new functionality
4. Update documentation as needed
5. Ensure all tests pass: `task test`

## 🙋 Support

For issues and questions:

- Check [docs/](./docs/) for detailed documentation
- Review [Testing Guide](docs/testing-guide.md) for testing help
- Open an issue for bugs or feature requests

## ✅ Implementation Status

- [x] Go module initialized
- [x] YAML-based configuration with environment overrides
- [x] AEAD encryption (AES-256-GCM)
- [x] Opaque token generation with JWT encryption
- [x] Dynamic client registration with encrypted credentials
- [x] OAuth authorization code flow with PKCE
- [x] Token exchange and validation
- [x] MCP request forwarding with auth middleware
- [x] Claims mapping to HTTP headers
- [x] Gin-based HTTP server with graceful shutdown
- [x] Comprehensive test suite
- [x] Documentation (README, design docs, flow diagrams)
- [x] Task runner for common operations
- [x] Test MCP server for integration testing
- [ ] Refresh token implementation
- [ ] Rate limiting
- [ ] Advanced monitoring and metrics
- [ ] OpenAPI specification
