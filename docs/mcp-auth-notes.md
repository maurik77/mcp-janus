# MCP Authorization & Security Best Practices Summary

**Source Documents:**
- https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices

**Date Retrieved:** October 30, 2025

---

## 1. Overview

### Purpose
The Model Context Protocol (MCP) provides **optional** authorization capabilities at the transport level for HTTP-based transports. MCP clients make requests to restricted MCP servers on behalf of resource owners.

### Standards Compliance
MCP authorization is based on:
- **OAuth 2.1** (IETF draft-ietf-oauth-v2-1-13)
- **OAuth 2.0 Authorization Server Metadata** (RFC 8414)
- **OAuth 2.0 Dynamic Client Registration Protocol** (RFC 7591)
- **OAuth 2.0 Protected Resource Metadata** (RFC 9728)
- **Resource Indicators for OAuth 2.0** (RFC 8707)

---

## 2. Roles & Architecture

### OAuth 2.1 Roles in MCP
1. **MCP Server** = OAuth 2.1 Resource Server
   - Accepts and responds to protected resource requests using access tokens
   - MUST implement RFC 9728 (Protected Resource Metadata)
   - MUST validate tokens were issued specifically for it (audience binding)

2. **MCP Client** = OAuth 2.1 Client
   - Makes protected resource requests on behalf of resource owner
   - MUST use RFC 9728 for authorization server discovery
   - MUST use RFC 8414 for authorization server metadata

3. **Authorization Server**
   - Issues access tokens for use at the MCP server
   - MUST implement OAuth 2.1 with appropriate security measures
   - SHOULD support RFC 7591 (Dynamic Client Registration)
   - MUST provide RFC 8414 metadata

---

## 3. Required OAuth Flows

### Authorization Code Flow + PKCE
- **Primary flow** for public clients and user-interactive scenarios
- **PKCE is MANDATORY** (OAuth 2.1 requirement)
- Protects against authorization code interception/injection attacks
- Client creates secret verifier-challenge pair

### Client Credentials Flow
- For service-to-service authentication
- Used when no user interaction is required

### Refresh Token Flow
- Authorization servers SHOULD issue short-lived access tokens
- For public clients: MUST rotate refresh tokens on each use
- Reduces impact of leaked tokens

---

## 4. Discovery & Metadata

### Authorization Server Discovery
1. MCP client makes request to MCP server without token
2. MCP server responds with **401 Unauthorized** + `WWW-Authenticate` header
3. Header indicates Protected Resource Metadata URL (RFC 9728)
4. Metadata document contains `authorization_servers` field (array)
5. Client selects appropriate authorization server per RFC 9728 §7.6

### Authorization Server Metadata
- MCP clients MUST fetch OAuth 2.0 Authorization Server Metadata (RFC 8414)
- Provides endpoints: authorization, token, registration, etc.
- Provides supported capabilities: grant types, response types, scopes, etc.

---

## 5. Dynamic Client Registration

### Requirements
- MCP clients and authorization servers **SHOULD** support RFC 7591
- Enables automatic registration without user interaction
- Critical for MCP because clients may not know all servers in advance

### Alternatives (when not supported)
1. Hardcode client ID/credentials for specific authorization servers
2. Provide UI for users to enter credentials after manual registration

---

## 6. Resource Parameter Implementation (RFC 8707)

### Critical Security Requirement
- MCP clients **MUST** include `resource` parameter in:
  - Authorization requests
  - Token requests
- Explicitly specifies target resource (MCP server)
- Binds tokens to their intended audience

### Canonical MCP Server URI
Format: `<scheme>://<host>[:<port>][<path>]`

**Valid examples:**
```
https://mcp.example.com/mcp
https://mcp.example.com
https://mcp.example.com:8443
https://mcp.example.com/server/mcp
```

**Invalid examples:**
```
mcp.example.com                    (missing scheme)
https://mcp.example.com#fragment   (contains fragment)
```

**Best practices:**
- Use lowercase scheme and host
- Omit trailing slash unless semantically significant
- Be as specific as possible (include path if needed)

**Example authorization request:**
```
&resource=https%3A%2F%2Fmcp.example.com
```

---

## 7. Access Token Usage

### Token Requirements
1. **MUST** use `Authorization` header (OAuth 2.1 §5.1.1):
   ```
   Authorization: Bearer <access-token>
   ```
2. **MUST NOT** include tokens in URI query strings
3. **MUST** include authorization in **every HTTP request** (even same session)

### Token Validation (MCP Server)
- **MUST** validate tokens per OAuth 2.1 §5.2
- **MUST** validate token audience binding (RFC 8707 §2)
- **MUST** verify token was issued specifically for this MCP server
- **MUST NOT** accept tokens issued for other resources
- **MUST NOT** pass through tokens to downstream services

### Token Validation (MCP Client)
- **MUST NOT** send tokens not issued by MCP server's authorization server

---

## 8. Security Requirements

### 8.1 Token Audience Binding & Validation
- **CRITICAL:** Prevents token misuse across services
- MCP clients MUST include `resource` parameter
- MCP servers MUST validate audience claims
- **NO TOKEN PASSTHROUGH** - see §8.2

### 8.2 Token Passthrough (FORBIDDEN)
**Anti-pattern:** Accepting tokens without validating they were issued for the MCP server, then forwarding to downstream APIs.

**Why it's forbidden:**
1. **Security Control Circumvention** - bypasses rate limiting, request validation, monitoring
2. **Accountability Issues** - cannot distinguish between MCP clients; audit trails broken
3. **Data Exfiltration Risk** - stolen tokens can be used as proxy without validation
4. **Trust Boundary Violations** - breaks assumptions about origin and behavior
5. **Future Compatibility** - makes evolving security model difficult

**Mitigation:**
- MCP servers MUST NOT accept tokens not explicitly issued for them
- If accessing upstream APIs: obtain separate tokens from upstream authorization server
- NEVER forward client tokens to upstream services

### 8.3 Token Theft Mitigation
- Implement secure token storage (OAuth 2.1 §7.1)
- Issue short-lived access tokens
- Rotate refresh tokens for public clients
- Revoke on suspicion

### 8.4 Communication Security
- All authorization server endpoints **MUST** use HTTPS
- All redirect URIs **MUST** be HTTPS or `localhost` (dev only)
- Follow OAuth 2.1 §1.5

### 8.5 Authorization Code Protection
- MCP clients **MUST** implement PKCE (OAuth 2.1 §7.5.2)
- Prevents code interception and injection attacks

### 8.6 Open Redirection Prevention
- MCP clients **MUST** register redirect URIs
- Authorization servers **MUST** validate exact redirect URIs
- MCP clients **SHOULD** use and verify state parameters
- Authorization servers **MUST** prevent redirecting to untrusted URIs (OAuth 2.1 §7.12.2)

### 8.7 Confused Deputy Problem
**Context:** MCP proxy servers connecting clients to third-party APIs

**Attack scenario:**
1. User authenticates via MCP proxy to third-party API
2. Third-party AS sets consent cookie for proxy's static client ID
3. Attacker sends malicious link with crafted auth request + dynamic client ID
4. Cookie causes consent screen to be skipped
5. Authorization code redirected to attacker's server
6. Attacker exchanges code for tokens without user consent

**Mitigation:**
- MCP proxy servers using static client IDs **MUST** obtain user consent for each dynamically registered client before forwarding to third-party authorization servers

### 8.8 Session Hijacking Prevention
**DO NOT authenticate via session IDs**

**Attack vectors:**
1. **Session Hijack Prompt Injection** - attacker injects events into shared queue using stolen session ID
2. **Session Hijack Impersonation** - attacker uses stolen session ID to impersonate user

**Mitigations:**
- MCP servers with authorization **MUST** verify all inbound requests
- MCP servers **MUST NOT** use sessions for authentication
- **MUST** use secure, non-deterministic session IDs (UUIDs with crypto RNG)
- **SHOULD** bind session IDs to user-specific info (format: `<user_id>:<session_id>`)
- Rotate or expire session IDs regularly

---

## 9. Error Handling

### HTTP Status Codes
| Code | Status      | Meaning                                      |
|------|-------------|----------------------------------------------|
| 401  | Unauthorized| Authorization required or token invalid     |
| 403  | Forbidden   | Invalid scopes or insufficient permissions  |
| 400  | Bad Request | Malformed authorization request             |

### Token Expiry
- Invalid or expired tokens **MUST** receive HTTP 401 response

---

## 10. Transport Requirements

### HTTP-Based Transports
- **SHOULD** conform to this specification
- OAuth 2.1 authorization flows apply

### STDIO Transports
- **SHOULD NOT** follow this specification
- Retrieve credentials from environment instead

### Alternative Transports
- **MUST** follow established security best practices for their protocol

---

## 11. Key Implementation Requirements for MCP Proxy

### For Our MCP Proxy Server Implementation

#### As OAuth Client (to upstream Authorization Server):
1. Implement OAuth 2.1 Authorization Code + PKCE flow
2. Implement Dynamic Client Registration (RFC 7591)
3. Use Protected Resource Metadata (RFC 9728) for AS discovery
4. Fetch Authorization Server Metadata (RFC 8414)
5. Always include `resource` parameter in auth/token requests
6. Validate state parameters
7. Store tokens securely
8. Handle token refresh with rotation

#### As OAuth Resource Server (to MCP client):
1. Implement Protected Resource Metadata (RFC 9728)
2. Return `WWW-Authenticate` header on 401 responses
3. Validate every incoming access token
4. Verify audience binding (token issued for this proxy)
5. Reject tokens with wrong audience
6. Use `Authorization: Bearer` header only
7. Return appropriate error codes (401, 403, 400)

#### As Proxy/Intermediary:
1. **NEVER pass through tokens from client to upstream**
2. Issue **own opaque bearer tokens** to MCP clients
3. Obtain separate tokens for upstream API access
4. Validate all inbound requests (not session-based auth)
5. Implement secure session IDs if needed for correlation (not auth)
6. For static client IDs: obtain user consent for each dynamic client

#### HTTPS & Security:
1. Enforce HTTPS for all endpoints (except localhost dev)
2. Validate redirect URIs strictly
3. Implement rate limiting
4. Use structured logging (no secrets in logs)
5. Short-lived access tokens, rotating refresh tokens
6. Secure key storage (KMS or OS secret store)

---

## 12. Summary Checklist for MCP Proxy Implementation

- [ ] OAuth 2.1 Authorization Code + PKCE flow
- [ ] OAuth 2.1 Client Credentials flow
- [ ] Dynamic Client Registration (RFC 7591)
- [ ] Protected Resource Metadata (RFC 9728) - server discovery
- [ ] Authorization Server Metadata (RFC 8414) - endpoint discovery
- [ ] Resource parameter (RFC 8707) in all auth/token requests
- [ ] Audience validation for all incoming tokens
- [ ] Issue own opaque bearer tokens to MCP clients
- [ ] Separate token acquisition for upstream APIs (no passthrough)
- [ ] HTTPS enforcement (except localhost)
- [ ] Redirect URI validation
- [ ] State parameter validation
- [ ] PKCE implementation
- [ ] Secure token storage
- [ ] Refresh token rotation
- [ ] Rate limiting
- [ ] Structured logging (no secrets)
- [ ] Proper error handling (401, 403, 400)
- [ ] Session security (non-auth, user-bound)
- [ ] User consent for dynamic clients (if using static upstream client ID)

---

## 13. References

### RFCs & Standards
- OAuth 2.1: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-13
- RFC 8414: OAuth 2.0 Authorization Server Metadata
- RFC 7591: OAuth 2.0 Dynamic Client Registration
- RFC 9728: OAuth 2.0 Protected Resource Metadata
- RFC 8707: Resource Indicators for OAuth 2.0
- RFC 9068: JSON Web Token (JWT) Profile for OAuth 2.0 Access Tokens

### MCP Specifications
- MCP Authorization: https://modelcontextprotocol.io/specification/2025-06-18/basic/authorization
- MCP Security Best Practices: https://modelcontextprotocol.io/specification/2025-06-18/basic/security_best_practices
