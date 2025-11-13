---
applyTo: '**'
---
# GitHub Copilot – Repository Instructions
**Project goal:** Implement a secure **MCP Proxy Server** in **Go (Golang)** that sits between an MCP client and a protected MCP server and **manages all communication**.  
The proxy must implement **OAuth 2.0 / OAuth 2.1–aligned flows** and **issue its own opaque bearer token** to the MCP client (not a passthrough of upstream tokens).

> 🔎 Before generating code or making design decisions, **retrieve and read** the following specification pages, and anchor all work to them:
> 1. https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization  
> 2. https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices  

If anything in this repo conflicts with those documents, prefer the specs above.

---

## Non-negotiable security rules

1. **No token passthrough.** Never accept or forward tokens not issued for this MCP proxy. Validate audience and `resource` binding.  
2. **HTTPS only.** All OAuth endpoints and redirects must be HTTPS (localhost is the only HTTP exception for dev).  
3. **Authorization bearer usage.** Put access tokens only in the `Authorization: Bearer …` header; **never** in query strings.  
4. **Short-lived tokens, rotating refresh tokens.** Favor short TTLs for access tokens (minutes), rotate refresh tokens, revoke on suspicion.  
5. **Opaque bearer tokens for the client.** The proxy **must issue its own opaque bearer token** to the MCP client. The opaque value’s payload is **encrypted** and must include at minimum:
   - `rtid` — internal “real token id” (reference to upstream credentials or session key)  
   - `exp` — absolute expiry for **this opaque token**  
   - *(Recommended)* `aud`, `scp`, `ver`, `kid`  
   Use AEAD (AES-GCM or XChaCha20-Poly1305) with server-held keys. Sign or MAC appropriately.  
6. **Key management.** Store keys in a KMS or OS secret store; support rotation via `kid`.  
7. **Session discipline.** Do not authenticate via session IDs; any correlation IDs must be random and server-bound.  
8. **Dynamic Client Registration.** Use RFC 7591 where possible. Enforce per-client consent flows.  
9. **Comprehensive logging without secrets.** Log decision points and identifiers, **never** secrets or raw tokens.

---

## Breakdown approach (always do this first)

### 1. Discover & Align
- Fetch and summarize the two MCP docs above into `docs/mcp-auth-notes.md`.  
- List required OAuth flows (Auth Code + PKCE for public, Client Credentials for service-to-service, refresh).  
- Identify transport requirements and metadata discovery endpoints.  

### 2. Design
- Draw component diagram (proxy, upstream AS, MCP server, client).  
- Define Go interfaces for:
  - `OAuthProvider` (auth flow & token exchange)
  - `TokenStore`
  - `CryptoService` (AEAD + key rotation)
  - `MCPClient` (validated proxy forwarding)
- Define proxy endpoints:
  - `POST /auth/authorize`
  - `GET  /auth/callback`
  - `POST /token` (issues opaque token)
  - `/* MCP routes */` (forwarding layer)
- Define `OpaqueTokenPayload` struct with JSON fields `{ rtid, exp, aud, scp, ver }`.  
- Choose AEAD (e.g., Go’s `crypto/aes` + `cipher.NewGCM` or `golang.org/x/crypto/chacha20poly1305`).  

### 3. Scaffold
- Go idiomatic structure:
   cmd/proxy/main.go
   internal/oauth/
   internal/crypto/
   internal/tokens/
   internal/mcp/
   pkg/http/
- Use Go modules (`go.mod`, `go.sum`).  
- Add configuration via `env` + `internal/config` (with `os.Getenv` and sensible defaults).  

### 4. Implement
- Implement OAuth discovery (RFC 8414).  
- Auth Code + PKCE and Client Credentials flows.  
- Token store (`rtid → UpstreamCredentials`), using in-memory + pluggable backend (Redis or DB).  
- Opaque token generation with AEAD encryption and `kid`-based rotation.  
- Audience/resource validation middleware before forwarding MCP calls.  
- Proper error handling with Go idioms: `errors.Is`, wrapped errors (`fmt.Errorf("…: %w", err)`), and contextual logging.

### 5. Harden
- Enforce HTTPS and strict redirect URIs.  
- Use Go’s `net/http` with timeouts, context cancellation, and `http.Server` shutdown hooks.  
- Apply rate limiting (`golang.org/x/time/rate`).  
- Implement structured logging (`log/slog` or `zap`) — no secrets.  
- Unit tests: crypto, expiry, audience/resource checks, error paths.  
- Integration tests: full OAuth + proxied MCP call.

### 6. Docs & Ops
- Write `README.md` with env vars, run scripts, and threat model summary.  
- Provide `scripts/gen-keys.go` and `scripts/rotate-keys.go`.  
- Add `openapi.yaml` for proxy endpoints.  

---

## Implementation checklist
- [ ] Go module initialized (`go mod init mcp-proxy`).  
- [ ] `internal/config` reads env vars and validates configuration.  
- [ ] OAuth discovery and token exchange implemented idiomatically with `net/http`.  
- [ ] `internal/tokens` implements opaque token creation/verification.  
- [ ] `internal/crypto` manages AEAD + key rotation.  
- [ ] `internal/mcp` implements forwarding logic with upstream token injection.  
- [ ] `cmd/proxy/main.go` uses `context` cancellation and graceful shutdown.  
- [ ] Tests >80% coverage for crypto, token validation, and auth flow.  

---

## Idiomatic Go Guidelines

1. **Project layout:**  
 - Use `internal` packages to encapsulate logic.  
 - Keep interfaces minimal; define them where they’re consumed.  
 - Use `cmd/proxy/main.go` as entry point only for wiring.

2. **Error handling:**  
 - Return `error` values, not panics.  
 - Use `errors.Is` / `errors.As` and wrap with context.  

3. **Concurrency:**  
 - Use `context.Context` for request scoping.  
 - Prefer channels or `sync` primitives for background tasks.  
 - Handle shutdown with context cancellation and signal handling.  

4. **Security libraries:**  
 - Use standard library crypto (`crypto/aes`, `crypto/rand`, `crypto/hmac`, `encoding/base64`) or `x/crypto` packages.  
 - Never use home-grown crypto.  

5. **Testing:**  
 - Use Go’s built-in `testing` framework.  
 - Favor table-driven tests.  
 - Mock external dependencies (HTTP, KMS, etc.) with interfaces.  

6. **Style & Quality:**  
 - Follow `golangci-lint` recommendations.  
 - Use `gofmt`, `goimports`, and `staticcheck`.  
 - Keep functions small, cohesive, and documented (`// Comment` style).  

---

## Deliverables for PRs created by the agent
- ✅ Working Go-based MCP Proxy implementing OAuth 2.0/2.1  
- ✅ `SECURITY.md` explaining opaque token crypto, key rotation, and audience binding  
- ✅ `README.md` with local runbook and threat model summary  
- ✅ Unit & integration tests (>80%)  
- ✅ `docs/mcp-auth-notes.md` summarizing retrieved MCP specs  

---

## References
- MCP Authorization Spec (2025-06-18)  
- MCP Security Best Practices (2025-06-18)  
- OAuth 2.1 (IETF draft)  
- Go standard library `net/http`, `crypto/aes`, `context`, `time`, `errors`, `log/slog`