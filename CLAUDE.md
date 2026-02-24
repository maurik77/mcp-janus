# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCP Janus is an OAuth 2.1-compliant MCP (Model Context Protocol) Proxy Server written in Go. It sits between MCP clients and protected MCP servers, managing OAuth 2.1 flows with PKCE, issuing opaque encrypted bearer tokens (AES-256-GCM), and forwarding authenticated requests to upstream MCP servers. The client never sees real IdP tokens.

## Build & Development Commands

This project uses [Task](https://taskfile.dev/) as its build tool. Go version: 1.25.3.

```bash
task build              # Build proxy binary → ./bin/mcpproxy
task build-testserver   # Build test server → ./bin/mcpserver
task run                # Build & run proxy (requires MCP_IDP_CLIENT_SECRET env var)
task run-testserver     # Run the fake MCP weather server on :8081
task start-all          # Run both proxy and test server
task test               # Run all tests: go test ./... -v
task coverage           # Tests with coverage + HTML report
task lint               # golangci-lint run ./...
task fmt                # gofmt + goimports
task security           # gosec security scan
task install            # go mod download + verify
```

Run a single test: `go test ./internal/infrastructure/wire/ -run TestTokenHandler -v`

## Architecture

```
MCP Client → [opaque bearer token] → Proxy (Gin HTTP) → [real IdP token] → Upstream MCP Server
                                        ↕
                                   Identity Provider (OAuth 2.1 + PKCE)
```

**Core flow**: Client registers via RFC 7591 → OAuth authorization code flow with PKCE → proxy encrypts IdP token into opaque bearer → client uses opaque token → proxy decrypts, validates JWT, forwards with real token to upstream.

### Key Packages

- **`cmd/proxy/main.go`** — Entry point. Loads config, inits telemetry, starts Gin server with graceful shutdown.
- **`cmd/mcpserver/main.go`** — Standalone fake weather MCP server for testing.
- **`internal/infrastructure/wire/gin.go`** — HTTP router setup, all endpoint handlers, middleware stack (logger, recovery, OTel, timeout, metrics).
- **`internal/service/auth/impl.go`** — Core auth logic: client registration, OAuth flow (authorize/callback/token exchange), JWT validation with JWKS, refresh tokens. This is the main business logic file.
- **`internal/service/auth/jwks.go`** — JWKS key fetching from IdP for JWT validation.
- **`internal/service/auth/openidconfig.go`** — OpenID Connect discovery configuration fetching.
- **`internal/service/metadata/`** — RFC 9728 OAuth Protected Resource Metadata and OpenID discovery responses.
- **`internal/server/impl.go`** — Reverse proxy implementation: auth middleware (decrypt opaque token, validate JWT), proxy handler (forward to upstream with real token), claims-to-headers mapping.
- **`internal/utility/encryption.go`** — AES-256-GCM AEAD encryption/decryption for opaque tokens, client IDs, and refresh tokens.
- **`internal/infrastructure/config/config.go`** — Viper-based YAML config with `MCP_` prefixed env var overrides.
- **`internal/infrastructure/telemetry/`** — OpenTelemetry tracing + metrics setup with OTLP exporters.

### Design Patterns

- **Interface-based DI**: Services (`auth.Service`, `metadata.Service`, `server.Proxy`) are interfaces injected in `wire/gin.go`.
- **Opaque token architecture**: All tokens issued to clients are AES-256-GCM encrypted blobs. The proxy decrypts them to retrieve the real IdP JWT before forwarding upstream.
- **Claims mapping**: IdP JWT claims are mapped to HTTP headers (configurable in `config.yaml` under `idp.claims_mapping`) and injected into upstream requests.
- **Table-driven tests**: Test files in `internal/infrastructure/wire/` use parameterized test cases with mock auth service implementations (`mocks_test.go`).

## Configuration

Main config: `config.yaml`. Environment overrides use `MCP_` prefix (e.g., `MCP_IDP_CLIENT_SECRET`, `MCP_PROXY_BASE_URL`). See `.env.example` for all supported env vars.

Key sections: `proxy` (listen addr, TLS, logging), `idp` (OAuth client config, scopes, claims mapping, JWKS), `encryption` (master key), `upstream` (target MCP server), `telemetry` (OTLP endpoint).

## Security Rules (from Copilot instructions)

- **No token passthrough** — never forward tokens not issued for this proxy; validate audience and resource binding.
- **Opaque bearer tokens only** — client never sees real IdP tokens; all issued tokens are AEAD-encrypted.
- **Authorization header only** — tokens go in `Authorization: Bearer`, never in query strings.
- **No secrets in logs** — log decision points and identifiers, never raw tokens or secrets.
- **HTTPS required** — all OAuth endpoints must use HTTPS (localhost HTTP exception for dev).

## API Endpoints

- `GET /.well-known/openid-configuration` / `/.well-known/oauth-protected-resource` — Discovery
- `POST /register` — Dynamic client registration (RFC 7591)
- `GET /auth` — OAuth authorization initiation
- `GET /callback` — OAuth callback from IdP
- `POST /token` — Token exchange (auth code → opaque access token)
- `POST /refresh` — Token refresh
- `GET/POST /mcp/*` — Authenticated MCP proxy (auth middleware applied)
- `GET /health` — Health check

## Docker

```bash
docker-compose up -d                                        # Proxy + test server
docker-compose -f docker-compose.observability.yaml up -d   # Jaeger, Prometheus, Grafana, OTel Collector
```

## MCP Specification References

Authoritative specs that govern implementation decisions:
- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
