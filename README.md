# MCP Janus

<p align="center">
  <img src="logo.svg" alt="MCP Janus" width="200" height="200"/>
</p>

[![Go](https://img.shields.io/badge/Go-1.24+-00ADD8?logo=go&logoColor=white)](https://golang.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![MCP Spec](https://img.shields.io/badge/MCP%20spec-2025--06--18-blueviolet)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
[![OAuth](https://img.shields.io/badge/OAuth-2.1%20%2B%20PKCE-orange)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
[![RFC 7591](https://img.shields.io/badge/RFC-7591%20DCR-blue)](https://datatracker.ietf.org/doc/html/rfc7591)

**An OAuth 2.1 proxy that gives MCP servers enterprise-grade security without touching a line of server code.**

---

## The Problem

Most MCP proxies solve the auth problem the wrong way: they receive the real IdP JWT from the authorization server and hand it straight to the MCP client. The client can now decode that JWT, read every claim, replay it against the IdP, and discover your identity provider's internals — a direct violation of the [MCP authorization spec](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization), which explicitly forbids forwarding tokens not issued for the proxy itself.

The security impact is real:

- The client learns your IdP URL, tenant, audience, and user claims
- A stolen token is reusable against both the proxy **and** the upstream IdP
- There is no boundary between "token for the proxy" and "token for everything else"

## What Janus Does

Janus sits in front of any MCP server and runs the complete OAuth 2.1 + PKCE flow on behalf of clients. After exchanging an authorization code with the real IdP, it **encrypts the IdP JWT with AES-256-GCM** and gives the client an opaque blob instead. On every subsequent request it decrypts, validates, and forwards the real JWT upstream — invisibly.

**The client never sees, decodes, or replays the real token. Zero token passthrough. Full MCP spec compliance.**

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
```

## Who Is This For?

- **Platform engineers** deploying MCP servers in production who need real security, not duct-tape auth
- **Enterprise teams** integrating Claude or ChatGPT with internal tools behind an IdP (Azure AD B2C, Okta, Keycloak, Auth0)
- **MCP server developers** who want OAuth 2.1 compliance without reimplementing auth from scratch
- **Security teams** auditing AI integrations for token leakage and spec compliance

---

## Key Features

### Security

- **Opaque encrypted tokens** — AES-256-GCM (AEAD) wraps every IdP JWT; clients only ever see ciphertext
- **No token passthrough** — proxy issues its own tokens, never forwards client tokens upstream
- **JWT validation** — full claim validation (expiry, audience, issuer) with JWKS key fetching and automatic rotation
- **Claims-to-headers mapping** — configurable IdP claim injection into upstream HTTP headers
- **Encrypted client credentials** — dynamic registration returns AEAD-encrypted `client_id` / `client_secret`
- **Self-issued token mode** — Janus can issue its own long-lived tokens (configurable TTL) for MCP clients like Claude and ChatGPT that do not support token refresh

### Standards Compliance

- **OAuth 2.1 + PKCE** — authorization code flow with S256 code challenge; public clients (no `client_secret`) fully supported
- **RFC 7591** — dynamic client registration with complete §3.2.1 response
- **RFC 8414** — OAuth 2.0 Authorization Server Metadata (`/.well-known/oauth-authorization-server`)
- **RFC 9728** — protected resource metadata including `bearer_methods_supported: ["header"]`
- **OpenID Connect Discovery** — `/.well-known/openid-configuration`
- **RFC 9207** — `iss` parameter in authorization responses (AS mix-up protection)

### Operations

- **Single binary** — `go build` produces one static binary, zero runtime dependencies
- **OpenTelemetry** — distributed tracing and metrics (Jaeger, Prometheus, Grafana out of the box)
- **Docker Compose** — one-command proxy + full observability stack
- **Structured logging** — JSON logs, configurable level
- **Graceful shutdown** — clean connection draining on SIGTERM
- **CORS support** — opt-in for browser-based MCP clients (e.g. MCP Inspector)

---

## Quick Start

### Option A — Local testing with Keycloak (recommended for first run)

```bash
git clone https://github.com/maurik77/mcp-janus.git
cd mcp-janus

# Start Keycloak + MCP test server
docker compose -f docker-compose.keycloak.yaml up -d

# Bootstrap realm, client, and test user — writes .env.keycloak-dev
./scripts/keycloak/setup-keycloak.sh        # Linux/macOS
# .\scripts\keycloak\setup-keycloak.ps1     # Windows (PowerShell)

# Build and run the proxy
task build
cp config.keycloak-dev.yaml config.yaml
source .env.keycloak-dev && CONFIG_PATH=. ./bin/mcpproxy

# Run the full end-to-end test (opens browser for login)
./scripts/keycloak/test-proxy-flow.sh
```

See [docs/guide_keycloak.md](docs/guide_keycloak.md) for the complete Keycloak setup guide, including Windows (PowerShell) instructions.

### Option B — Bring your own IdP

```bash
git clone https://github.com/maurik77/mcp-janus.git
cd mcp-janus

go mod download
go build -o bin/mcpproxy ./cmd/proxy

# Edit config.yaml with your IdP's OIDC discovery URL and client credentials
export MCP_IDP_CLIENT_SECRET="your-idp-client-secret"
CONFIG_PATH=. ./bin/mcpproxy
```

Or use [Task](https://taskfile.dev/) shortcuts:

```bash
task install   # go mod download + verify
task build     # build → ./bin/mcpproxy
task run       # build + run (needs MCP_IDP_CLIENT_SECRET)
```

### Verify it's running

```bash
curl http://localhost:8080/health
# OK

curl http://localhost:8080/.well-known/oauth-protected-resource | jq .
```

---

## How It Works

### Standard opaque token flow

1. **Register** — client calls `POST /register` with redirect URIs. Proxy returns an AEAD-encrypted `client_id` and `client_secret` (RFC 7591 §3.2.1).
2. **Authorize** — client redirects to `GET /auth` with PKCE `code_challenge`. Proxy redirects to the real IdP.
3. **Callback** — IdP redirects back to `GET /callback`. Proxy receives the authorization code.
4. **Token exchange** — client calls `POST /token` with `code_verifier`. Proxy exchanges with the IdP, receives the real JWT, encrypts it with AES-256-GCM, and returns an opaque bearer to the client.
5. **Authenticated requests** — client sends `Authorization: Bearer <opaque>` to `/mcp/*`. Proxy decrypts, validates the JWT, maps claims to headers, and forwards with the real token.
6. **Refresh** — client calls `POST /refresh` with the encrypted refresh token. Proxy decrypts, refreshes with the IdP, re-encrypts, and returns a new opaque bearer.

### Self-issued token mode (`token_behavior: self_issued`)

Some MCP clients (Claude, ChatGPT) complete the OAuth flow once and never call `/refresh`. With the default `proxy` mode, sessions expire when the IdP token expires (typically 1 hour). The `self_issued` mode solves this:

1. After the initial IdP exchange, the JWT is validated **once** and claims are extracted.
2. Janus issues its own opaque token containing the **encrypted mapped claims** and a Janus-controlled expiry (`token_ttl`).
3. On every subsequent request the proxy decrypts the token, checks the expiry, and injects the claims as headers — **no JWKS call, no IdP contact**.
4. If `/refresh` is called, a new access token is issued from the same encrypted claims up to `token_max_ttl` without touching the IdP.

**Trade-offs:**

| | `proxy` | `self_issued` |
| --- | --- | --- |
| Token lifetime | IdP-controlled (e.g. 1 h) | Janus-controlled (e.g. 720 h) |
| IdP revocation effective within | ~1 h | up to `token_max_ttl` |
| JWKS call per request | yes (cached) | no |
| Claims freshness | refreshed at IdP token renewal | frozen until `token_max_ttl` |
| Clients without refresh support | session expires hourly | full `token_ttl` duration |

### Token encryption

- **Algorithm**: AES-256-GCM (AEAD — authenticated encryption with associated data)
- **Process**: real JWT → encrypt with 256-bit master key → random nonce per operation → base64url encode → opaque string
- **Decryption**: extract bearer → base64url decode → decrypt → parse JWT → validate claims

### Claims mapping

IdP JWT claims are mapped to upstream HTTP headers on every proxied request:

```yaml
idp:
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
    upn: X-UPN
```

The upstream MCP server receives clean HTTP headers — no JWT parsing, no IdP dependency.

---

## Configuration

Create `config.yaml` in the working directory (or use `MCP_`-prefixed environment variables):

```yaml
proxy:
  base_url: http://localhost:8080        # Canonical URL of this proxy
  listen_addr: ":8080"
  log_level: info                        # trace|debug|info|warn|error
  log_format: json
  cors:
    enabled: false                       # true for browser clients (e.g. MCP Inspector)
    allowed_origins:
      - http://localhost:6274
  token_behavior: proxy                  # proxy (default) | self_issued
  token_ttl: 24h                         # [self_issued] lifetime of each access token
  token_max_ttl: 168h                    # [self_issued] max window from original login

idp:
  client_id: your-idp-client-id
  client_secret: ""                      # use MCP_IDP_CLIENT_SECRET env var
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes:
    - openid
    - profile
    - email
  claims_mapping:
    sub: X-Sub
    name: X-Full-Name
    email: X-Email
  jwt_leeway: 10s

encryption:
  # Generate with: openssl rand -hex 32
  master_key: "your-64-char-hex-key"

upstream:
  name: my-mcp-server
  resource: https://mcp.example.com     # resource indicator for audience binding
  base_url: https://mcp.example.com
  path_prefix: /mcp

telemetry:
  enabled: true
  service_name: mcp-proxy
  otlp_endpoint: localhost:4318
```

Environment variable overrides:

```bash
export MCP_IDP_CLIENT_SECRET="your-secret"
export MCP_PROXY_BASE_URL="https://proxy.example.com"
export MCP_ENCRYPTION_MASTER_KEY="$(openssl rand -hex 32)"
export MCP_PROXY_CORS_ENABLED=true
export MCP_TOKEN_BEHAVIOR=self_issued
export MCP_TOKEN_TTL=720h
```

See [.env.example](.env.example) for the full list.

---

## API Endpoints

| Method | Path | Description |
| ------ | ---- | ----------- |
| `GET` | `/.well-known/openid-configuration` | OpenID Connect discovery |
| `GET` | `/.well-known/oauth-authorization-server` | Authorization server metadata (RFC 8414) |
| `GET` | `/.well-known/oauth-protected-resource` | Protected resource metadata (RFC 9728) |
| `POST` | `/register` | Dynamic client registration (RFC 7591) |
| `GET` | `/auth` | OAuth authorization with PKCE |
| `GET` | `/callback` | OAuth callback from IdP |
| `POST` | `/token` | Authorization code → opaque bearer |
| `POST` | `/refresh` | Refresh token exchange |
| `GET/POST` | `/mcp/*` | Authenticated MCP proxy |
| `GET` | `/health` | Health check |

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

See [docs/testing-guide.md](docs/testing-guide.md) for the full curl sequence.

---

## Observability

```bash
docker compose -f docker-compose.observability.yaml up -d
```

Launches Jaeger (traces), Prometheus (metrics), Grafana (dashboards), and the OpenTelemetry Collector. The proxy exports automatically when `telemetry.enabled: true`.

Key metrics:

| Metric | Description |
| ------ | ----------- |
| `mcp.proxy.auth.requests.total` | Auth requests by result |
| `mcp.proxy.token.exchange.duration` | Token exchange latency |
| `mcp.proxy.requests.total` | Proxy requests by method/path/status |
| `mcp.proxy.upstream.errors.total` | Upstream error counter |

See [docs/opentelemetry.md](docs/opentelemetry.md) for dashboard setup.

---

## Docker

```bash
# Proxy + MCP test server
docker compose up -d

# Full observability stack
docker compose -f docker-compose.observability.yaml up -d

# Both together
docker compose -f docker-compose.yaml -f docker-compose.observability.yaml up -d

# Keycloak dev environment
docker compose -f docker-compose.keycloak.yaml up -d
```

---

## Deployment

The `deploy.sh` script builds, tags, pushes, and deploys via Helm in one step:

```bash
export REGISTRY=myregistry.azurecr.io
./deploy.sh 1.0.0
```

Steps performed: `docker build` → tag + push to registry → update `deployment/values-dev.yaml` → `helm upgrade`.

---

## Contributing

1. Fork the repo and create a feature branch
2. Run `task fmt` before committing
3. Add tests for new functionality (table-driven preferred)
4. Ensure `task test` and `task lint` pass
5. Open a pull request with a clear description

If you're testing against a real IdP, the [Keycloak setup guide](docs/guide_keycloak.md) gives you a local IdP in under 5 minutes.

---

## References

### MCP Specifications

- [MCP Authorization (2025-06-18)](https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization)
- [MCP Security Best Practices](https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices)

### OAuth Standards

- [OAuth 2.1 (IETF Draft)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13)
- [RFC 7591: Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
- [RFC 8414: Authorization Server Metadata](https://datatracker.ietf.org/doc/html/rfc8414)
- [RFC 8707: Resource Indicators](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 9207: AS Issuer Identification](https://datatracker.ietf.org/doc/html/rfc9207)
- [RFC 9728: Protected Resource Metadata](https://datatracker.ietf.org/doc/html/rfc9728)

### Project Documentation

- [Architecture & Design](docs/design.md)
- [Auth Flow Diagrams](docs/auth-flow.md)
- [Keycloak Dev Setup](docs/guide_keycloak.md)
- [Testing Guide](docs/testing-guide.md)
- [OpenTelemetry Setup](docs/opentelemetry.md)
- [MCP Auth Spec Notes](docs/mcp-auth-notes.md)
