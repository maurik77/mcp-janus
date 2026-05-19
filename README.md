# MCP Janus

An OAuth 2.1 MCP proxy that encrypts IdP tokens into opaque AES-256-GCM bearers. Single Go binary, zero token passthrough.

## Why Janus?

The [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization) requires that proxies **never forward tokens not issued for themselves**. Most MCP auth proxies pass through the IdP JWT as-is, violating this requirement and leaking identity provider details to clients.

Janus solves this by encrypting every IdP JWT into an **opaque bearer token** using AES-256-GCM before handing it to the client. The client never sees, decodes, or replays the real token. On each request the proxy decrypts, validates the JWT, and forwards the real token upstream.

**Result**: full MCP spec compliance, zero token leakage, and the upstream server receives a valid IdP JWT with no extra integration.

## Key Features

### Security

- **Opaque encrypted tokens** -- AES-256-GCM (AEAD) wraps every IdP JWT; clients only see ciphertext
- **No token passthrough** -- proxy issues its own tokens, never forwards client tokens
- **JWT validation** -- full claim validation (expiry, audience, issuer) with JWKS key fetching
- **Claims-to-headers mapping** -- configurable IdP claim injection into upstream HTTP headers
- **Encrypted client credentials** -- dynamic registration returns AEAD-encrypted `client_id` / `client_secret`
- **CIMD SSRF guard** -- CIMD fetch blocks private/loopback IPs and enforces an optional domain allowlist
- **JTI replay protection** -- `private_key_jwt` assertions are single-use; replayed JTIs are rejected

### Standards Compliance

- **OAuth 2.1 + PKCE** -- authorization code flow with S256 code challenge
- **RFC 7591** -- dynamic client registration
- **RFC 9728** -- protected resource metadata for discovery
- **OpenID Connect Discovery** -- `.well-known/openid-configuration` endpoint
- **CIMD** -- OAuth Client ID Metadata Document (`draft-ietf-oauth-client-id-metadata-document-00`); `client_id` is an HTTPS URL the proxy fetches at runtime — no pre-registration required
- **RFC 7523 / `private_key_jwt`** -- JWT Bearer client assertions validated via `jwks_uri` from the CIMD document; JTI replay protection included
- **RFC 8707** -- resource indicators; clients bind tokens to a specific MCP server
- **RFC 9207** -- `iss` parameter appended to authorization response redirects (mix-up attack protection)

### Operations

- **OpenTelemetry** -- distributed tracing and business metrics (auth, token exchange, proxy, upstream errors)
- **Docker Compose** -- one-command proxy + observability stack (Jaeger, Prometheus, Grafana)
- **Structured logging** -- JSON logs, configurable level, no secrets in output
- **Graceful shutdown** -- clean connection draining on SIGTERM
- **Single binary** -- `go build` produces one static binary, no runtime dependencies

## Architecture

```text
MCP Client                        MCP Janus Proxy                    Upstream MCP Server
    │                                    │                                    │
    │  Authorization: Bearer <opaque>    │                                    │
    │ ──────────────────────────────────>│                                    │
    │                                    │ 1. Decrypt opaque token (AES-GCM)  │
    │                                    │ 2. Validate JWT (exp, aud, iss)    │
    │                                    │ 3. Map claims → HTTP headers       │
    │                                    │                                    │
    │                                    │  Authorization: Bearer <real JWT>  │
    │                                    │  X-Sub: user123                    │
    │                                    │ ──────────────────────────────────>│
    │                                    │                                    │
    │                                    │◄──────────────────────────────────│
    │◄──────────────────────────────────│                                    │
    │                                    │                                    │

    OAuth 2.1 + PKCE flow (register → authorize → callback → token exchange)
    is handled between the client and the proxy, coordinating with the IdP.
```

## Quick Start

### Prerequisites

- Go 1.24+ (or download a [release binary](https://github.com))
- An OAuth 2.1 / OpenID Connect identity provider
- [Task](https://taskfile.dev/) runner (optional, for convenience commands)

### Build and run

```bash
git clone https://github.com/user/mcp-janus.git
cd mcp-janus

# Install dependencies
go mod download

# Build
go build -o bin/mcpproxy ./cmd/proxy

# Set your IdP client secret (or put it in config.yaml)
export MCP_IDP_CLIENT_SECRET="your-idp-client-secret"

# Run
./bin/mcpproxy
```

Or use Task shortcuts:

```bash
task install        # go mod download + verify
task build          # build → ./bin/mcpproxy
task run            # build + run (needs MCP_IDP_CLIENT_SECRET)
```

### Verify it's running

```bash
curl http://localhost:8080/health
# OK

curl http://localhost:8080/.well-known/oauth-protected-resource | jq .
```

### Test server

The repo includes a fake MCP weather server for local testing:

```bash
task build-testserver   # build → ./bin/mcpserver
task run-testserver     # runs on :8081
task start-all          # proxy + test server together
```

See [docs/testing-guide.md](docs/testing-guide.md) for the full end-to-end test walkthrough.

## How It Works

### Opaque token flow

1. **Register** -- client calls `POST /register` with redirect URIs (RFC 7591), _or_ uses a URL as `client_id` (CIMD — no pre-registration needed). Proxy returns an AEAD-encrypted `client_id` and `client_secret` for registered clients.
2. **Authorize** -- client redirects to `GET /auth` with PKCE `code_challenge` and optional `resource` (RFC 8707). Proxy redirects to the IdP.
3. **Callback** -- IdP redirects back to `GET /callback`. Proxy appends `iss` to the redirect (RFC 9207) for mix-up attack protection.
4. **Token exchange** -- client calls `POST /token` with `code_verifier`. For CIMD clients with `private_key_jwt`, a signed JWT assertion is verified against the client's `jwks_uri`. Proxy exchanges the code with the IdP, encrypts the real JWT, and returns the opaque bearer.
5. **Authenticated requests** -- client sends `Authorization: Bearer <opaque>` to `GET/POST /mcp/*`. Proxy decrypts, validates the JWT, maps claims to headers, and forwards with the real token.
6. **Refresh** -- client calls `POST /refresh` with the encrypted refresh token. Proxy decrypts, refreshes with the IdP, re-encrypts, and returns a new opaque bearer.

### Token encryption detail

- **Algorithm**: AES-256-GCM (AEAD -- authenticated encryption with associated data)
- **Process**: real JWT → encrypt with 256-bit master key → random nonce per operation → base64url encode → opaque token string
- **Decryption**: extract bearer → base64url decode → decrypt with master key → parse JWT → validate claims

### Claims mapping

IdP JWT claims are mapped to HTTP headers on upstream requests:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

The upstream server receives these headers without needing to understand JWT or talk to the IdP.

For detailed architecture documentation see [docs/design.md](docs/design.md) and [docs/auth-flow.md](docs/auth-flow.md).

## Configuration

Create a `config.yaml` in the working directory (or set `MCP_`-prefixed environment variables):

```yaml
proxy:
  base_url: http://localhost:8080        # Canonical URL of this proxy
  issuer: ""                             # Issuer identifier (defaults to base_url if empty)
  listen_addr: ":8080"                   # Listen address
  log_level: info                        # trace|debug|info|warn|error|fatal|panic
  log_format: json                       # json
  # CIMD: OAuth Client ID Metadata Document support
  cimd_enabled: true                     # Accept URL-format client_id values
  cimd_allow_list: []                    # Domain allowlist; empty = any HTTPS URL accepted
  cimd_localhost_port_insensitive: false # Match localhost redirect URIs ignoring port (Claude Code compat)

idp:
  client_id: your-idp-client-id         # OAuth client ID at the IdP
  client_secret: ""                      # OAuth client secret (use MCP_IDP_CLIENT_SECRET env var)
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes:
    - openid
    - profile
    - email
  claims_mapping:                        # IdP JWT claim → upstream HTTP header
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
  jwt_leeway: 10s                        # Clock skew tolerance for JWT validation

encryption:
  # 256-bit hex key. Generate with: openssl rand -hex 32
  master_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

upstream:
  name: my-mcp-server                   # Upstream display name
  resource: https://mcp.example.com     # Resource identifier for audience binding
  base_url: https://mcp.example.com     # Upstream base URL
  path_prefix: /mcp                     # Path prefix for proxied requests

telemetry:
  enabled: true                          # Enable OpenTelemetry
  service_name: mcp-proxy                # Service name in traces/metrics
  service_version: 1.0.0
  otlp_endpoint: localhost:4318          # OTLP HTTP endpoint
```

Environment variable overrides use the `MCP_` prefix with underscores for nesting:

```bash
export MCP_IDP_CLIENT_SECRET="your-secret"
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_ENCRYPTION_MASTER_KEY="$(openssl rand -hex 32)"
```

See [.env.example](.env.example) for all supported variables.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/.well-known/openid-configuration` | OpenID Connect discovery |
| `GET` | `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `POST` | `/register` | Dynamic client registration (RFC 7591) |
| `GET` | `/auth` | OAuth authorization initiation (with PKCE) |
| `GET` | `/callback` | OAuth callback from IdP |
| `POST` | `/token` | Token exchange (auth code → opaque bearer) |
| `POST` | `/refresh` | Refresh token exchange |
| `GET/POST` | `/mcp/*` | Authenticated MCP proxy to upstream |
| `GET` | `/health` | Health check (returns `OK`) |

### Example: register a client

```bash
curl -s -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "My MCP Client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }' | jq .
```

See [docs/testing-guide.md](docs/testing-guide.md) for the full curl sequence (register → auth → token → proxy call).

## Observability

Start the full observability stack:

```bash
docker-compose -f docker-compose.observability.yaml up -d
```

This launches Jaeger (traces), Prometheus (metrics), Grafana (dashboards), and the OpenTelemetry Collector. The proxy exports traces and metrics automatically when `telemetry.enabled: true`.

Key metrics:

- `mcp.proxy.auth.requests.total` -- authentication requests by result
- `mcp.proxy.token.exchange.duration` -- token exchange latency histogram
- `mcp.proxy.requests.total` -- proxy requests by method/path/status
- `mcp.proxy.upstream.errors.total` -- upstream error counter

See [docs/opentelemetry.md](docs/opentelemetry.md) for configuration details, custom spans, and dashboard setup.

## Docker

```bash
# Proxy + test server
docker-compose up -d

# Full observability stack (Jaeger, Prometheus, Grafana, OTel Collector)
docker-compose -f docker-compose.observability.yaml up -d

# Both together
docker-compose -f docker-compose.yaml -f docker-compose.observability.yaml up -d
```

## Contributing

1. Fork the repo and create a feature branch
2. Run `task fmt` before committing
3. Add tests for new functionality (table-driven preferred)
4. Ensure `task test` passes
5. Ensure `task lint` passes (if golangci-lint is installed)
6. Open a pull request with a clear description

## References

### MCP Specifications

- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### OAuth Standards

- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591: Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 7523: JWT Bearer Client Assertions (`private_key_jwt`)](https://datatracker.ietf.org/doc/html/rfc7523)
- [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9207: Authorization Server Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)
- [CIMD: OAuth Client ID Metadata Document](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document)

### Project Documentation

- [Architecture & Design](docs/design.md)
- [Auth Flow Diagrams](docs/auth-flow.md)
- [Testing Guide](docs/testing-guide.md)
- [OpenTelemetry Setup](docs/opentelemetry.md)
- [MCP Auth Spec Notes](docs/mcp-auth-notes.md)
