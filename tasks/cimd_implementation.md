# CIMD & MCP Draft Authorization Implementation

**Spec reference:** [MCP Authorization Draft](https://modelcontextprotocol.io/specification/draft/basic/authorization)
**Key new RFC:** [draft-ietf-oauth-client-id-metadata-document-00](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00)

---

## Real-World CIMD Documents (Live)

### Claude Code — `https://claude.ai/oauth/claude-code-client-metadata`

```json
{
  "client_id": "https://claude.ai/oauth/claude-code-client-metadata",
  "client_name": "Claude Code",
  "client_uri": "https://claude.ai",
  "redirect_uris": [
    "http://localhost/callback",
    "http://127.0.0.1/callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

**Notes:** Public client (PKCE only). Redirect URIs have **no port** — Janus MUST allow
portless `localhost` URIs and match them against the actual redirect sent by the client,
which includes a port (e.g. `http://localhost:3118/callback`). See known bug in Claude Code
2.1.80-2.1.81 ([issue #37747](https://github.com/anthropics/claude-code/issues/37747)):
the published doc has portless URIs but the callback listener uses port 3118. Janus SHOULD
either support prefix matching for localhost or document the limitation clearly.

### ChatGPT — `https://chatgpt.com/oauth/client.json`

```json
{
  "client_id": "https://chatgpt.com/oauth/client.json",
  "client_name": "ChatGPT",
  "client_uri": "https://chatgpt.com/",
  "logo_uri": "https://persistent.oaistatic.com/sonic/misc/openai-logo.png",
  "redirect_uris": ["https://chatgpt.com/connector_platform_oauth_redirect"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "private_key_jwt",
  "token_endpoint_auth_signing_alg": "RS256",
  "jwks_uri": "https://chatgpt.com/oauth/jwks.json"
}
```

**Notes:** Confidential client using asymmetric key (`private_key_jwt` + RS256).
ChatGPT presents a signed JWT as the client assertion at the token endpoint, verified
against the public JWKS at `jwks_uri`. Redirect URI is an HTTPS server-side endpoint
(web connector, not local CLI). Janus MUST support `private_key_jwt` at the `/token`
endpoint to be compatible with ChatGPT.

### Key Differences

| | Claude Code | ChatGPT |
|---|---|---|
| Client type | Public (CLI) | Confidential (web) |
| Auth method | `none` (PKCE) | `private_key_jwt` RS256 |
| Redirect URI | `localhost` (portless) | `https://chatgpt.com/...` |
| JWKS | — | `https://chatgpt.com/oauth/jwks.json` |
| `logo_uri` | — | Yes |

---

## Context

The MCP authorization draft (2025-11-25+) introduces two major additions over the existing
RFC 7591 DCR approach already implemented in Janus:

1. **Client ID Metadata Documents (CIMD)** — The `client_id` is an HTTPS URL that the AS
   fetches at runtime to obtain client metadata. No pre-registration endpoint is needed.
   The spec says SHOULD support this (DCR demoted to MAY / backwards-compat fallback).

2. **Resource Indicators (RFC 8707)** — Clients MUST pass a `resource` parameter in both
   authorization and token requests, explicitly binding tokens to the target MCP server.

Additional smaller requirements:
- `iss` in authorization callback (RFC 9207)
- `client_id_metadata_document_supported: true` in AS metadata
- `authorization_response_iss_parameter_supported: true` in AS metadata

The proxy already handles #1 (AS to MCP clients) via opaque encrypted blobs + DCR. CIMD adds
a parallel path: if `client_id` looks like a URL, fetch and validate instead of decrypt.

---

## Architecture Impact

```
/auth request
  └─ client_id is HTTPS URL? ──yes──► FetchCIMD → ValidateCIMD → store URL in StateData
                               │
                              no
                               └──► DecodeClientID (existing encrypted blob path)

/callback
  └─ stateData.ClientID is URL? ──yes──► FetchCIMD (cache hit likely) → validate redirect_uri
                                 │
                                no
                                 └──► DecodeClientID (existing path)

/token (code exchange)
  └─ CIMD client_id → skip secret check (public client, PKCE-only)
  └─ regular client_id → existing validateClientCredentials
```

CIMD clients get opaque encrypted tokens from Janus just like regular clients — only the
registration/validation path differs.

---

## Checklist

### Phase 1 — CIMD Fetcher & Cache

- [ ] **1. Define `ClientIDMetadataDocument` struct** (`internal/service/auth/cimd.go`)
  - Fields: `ClientID`, `ClientName`, `RedirectURIs`, `GrantTypes`, `ResponseTypes`,
    `TokenEndpointAuthMethod`, `ClientURI`, `LogoURI`, `JwksURI`
  - All from `draft-ietf-oauth-client-id-metadata-document-00 §3`

- [ ] **2. Implement `isCIMDClientID(s string) bool`** (`internal/service/auth/cimd.go`)
  - Returns true if `s` is a valid `https://` URL with a non-empty path that contains no
    `.` or `..` segments, no fragment, no embedded credentials

- [ ] **3. Implement `FetchCIMD(ctx, rawURL string, httpClient) (*ClientIDMetadataDocument, error)`**
  - HTTPS scheme check (hard error if not)
  - SSRF guard: resolve hostname, reject RFC 1918 / loopback / link-local addresses
    (127.0.0.0/8, ::1, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, fc00::/7)
  - 5-second request timeout; 5 KB response cap (`io.LimitReader`)
  - Validate: `client_id` field in JSON must match fetched URL (exact string match)
  - Validate: `client_name` and `redirect_uris` are present and non-empty
  - Validate: `token_endpoint_auth_method` is NOT one of `client_secret_basic`,
    `client_secret_post`, `client_secret_jwt`; document MUST NOT contain `client_secret`
  - Return `invalid_client` error for all validation failures

- [ ] **4. Implement in-memory CIMD cache** (`internal/service/auth/cimd_cache.go`)
  - `cimdCache` struct with `sync.RWMutex` + `map[string]cimdCacheEntry`
  - Entry: `{doc *ClientIDMetadataDocument; expiresAt time.Time}`
  - `Get(url) (*ClientIDMetadataDocument, bool)` — returns nil if expired (passive expiry)
  - `Set(url, doc, maxAge time.Duration)` — caps maxAge at 86400s per spec
  - `ParseMaxAge(resp *http.Response) time.Duration` — reads `Cache-Control: max-age=N`,
    falls back to `Expires` header, falls back to default (1 hour)
  - Wire cache into `ProxyAuthHandler` as `cimdCache *cimdCache`

- [ ] **5. Implement `FetchCIMDCached(ctx, url, httpClient) (*ClientIDMetadataDocument, error)`**
  - Check cache first; on miss call `FetchCIMD`, store result; propagate errors uncached

### Phase 2 — Auth Service Integration

- [ ] **6. Branch on CIMD in `AuthenticateRequest`** (`internal/service/auth/impl.go`)
  - If `isCIMDClientID(req.ClientID)` → call `FetchCIMDCached` → validate
    `req.RedirectURI` against `doc.RedirectURIs` (exact match required)
  - If validation succeeds → proceed to build `StateData` with `ClientID = req.ClientID`
    (the raw URL, not an encrypted blob)
  - If validation fails → return `invalid_request` (no change to existing path)
  - Existing encrypted blob path unchanged

- [ ] **7. Branch on CIMD in `ManageAuthorizationCode`** (`internal/service/auth/impl.go`)
  - After `DecodeStateData`, check if `stateData.ClientID` is a CIMD URL
  - CIMD path: call `FetchCIMDCached`, validate `stateData.RedirectURI` against doc
  - Non-CIMD path: existing `DecodeClientID` call
  - Add `iss` query param to the redirect URL:
    `q.Set("iss", h.issuer())` where `h.issuer()` returns `cfg.Proxy.Issuer` or `cfg.Proxy.BaseURL`

- [ ] **8. Branch on CIMD in `validateClientCredentials`** (`internal/service/auth/impl.go`)
  - If `isCIMDClientID(clientID)` → return nil immediately (public client, PKCE-only)
  - Non-CIMD path: existing logic unchanged

- [ ] **9. Branch on CIMD in `RefreshToken`** (`internal/service/auth/impl.go`)
  - Same CIMD check before `validateClientCredentials`

### Phase 3 — Resource Indicators (RFC 8707)

- [ ] **10. Add `Resource` to `AuthenticateRequest`, `AccessTokenRequest`, `StateData`**
      (`internal/service/auth/types.go`)
  - `AuthenticateRequest.Resource string \`form:"resource"\``
  - `AccessTokenRequest.Resource string \`form:"resource"\``
  - `StateData.Resource string \`json:"res"\`` (new field — backward compatible, empty = absent)

- [ ] **11. Thread `resource` through auth flow** (`internal/service/auth/impl.go`)
  - `AuthenticateRequest`: store `req.Resource` in `stateData.Resource`
  - `AuthenticateRequest`: if `req.Resource != ""`, add `resource=<value>` param to upstream
    IdP authorization URL (`oauth2.SetAuthURLParam`)
  - `RetrieveAccessToken`: if `req.Resource != ""`, pass `resource=<value>` in IdP token
    exchange params

### Phase 4 — Metadata Updates

- [ ] **12. Update AS metadata responses** (`internal/service/metadata/metadata.go`)
  - `OpenIDConfiguration()`: add `"client_id_metadata_document_supported": true`
  - `OpenIDConfiguration()`: add `"authorization_response_iss_parameter_supported": true`
  - `AuthorizationServerMetadata()`: same two additions
  - (Optional) add `"resource_indicators_supported": true` to both

### Phase 5 — Config Additions

- [ ] **13. Add CIMD config fields** (`internal/infrastructure/config/config.go`)
  - Add to `Proxy` struct:
    ```go
    CIMDEnabled     bool          `mapstructure:"cimd_enabled"`
    CIMDAllowList   []string      `mapstructure:"cimd_allow_list"`
    CIMDCacheMaxAge time.Duration `mapstructure:"cimd_cache_max_age"`
    ```
  - Add `viper.BindEnv` bindings: `MCP_PROXY_CIMD_ENABLED`, `MCP_PROXY_CIMD_CACHE_MAX_AGE`
  - Defaults: `cimd_enabled: true`, `cimd_cache_max_age: 1h`
  - When `cimd_enabled: false`, `AuthenticateRequest` treats URL client_ids as `invalid_request`

- [ ] **14. Apply domain allowlist in `FetchCIMDCached`**
  - If `cfg.Proxy.CIMDAllowList` is non-empty, reject `client_id` URLs whose hostname
    does not match any entry before issuing the HTTP request

### Phase 6 — Tests

- [ ] **15. Unit tests for CIMD fetcher** (`internal/service/auth/cimd_test.go`)
  - Happy path: valid doc, `client_id` matches URL, redirect URI valid
  - Error: `client_id` in doc does not match fetch URL
  - Error: missing `client_name`
  - Error: missing `redirect_uris`
  - Error: `token_endpoint_auth_method: "client_secret_basic"` rejected
  - Error: `client_secret` field present in doc → rejected
  - Error: HTTP URL (non-HTTPS) → rejected
  - Error: private IP URL → SSRF blocked
  - Error: response > 5KB → truncated / error

- [ ] **16. Unit tests for CIMD cache** (`internal/service/auth/cimd_cache_test.go`)
  - Cache hit returns stored doc
  - Cache miss triggers fetch
  - Expired entry triggers re-fetch
  - `ParseMaxAge` correctly reads `Cache-Control: max-age=N`
  - `ParseMaxAge` correctly reads `Expires` header
  - Default TTL used when neither header present
  - Max-age capped at 86400s

- [ ] **17. Unit tests: `AuthenticateRequest` with CIMD client** (`internal/service/auth/`)
  - CIMD URL as `client_id` → valid redirect URI in doc → returns auth URL
  - CIMD URL as `client_id` → redirect URI NOT in doc → `invalid_request`
  - CIMD URL as `client_id` → fetch fails (network error) → `invalid_request`
  - Existing encrypted blob client_id still works (regression)

- [ ] **18. Unit tests: `ManageAuthorizationCode` with CIMD state**
  - CIMD URL in `stateData.ClientID` → redirect validated, `iss` appended to redirect
  - Existing encrypted blob in state still works (regression)
  - ISS param present in redirect URL for both CIMD and non-CIMD paths

- [ ] **19. Unit tests: `validateClientCredentials` with CIMD**
  - CIMD URL → always passes (no secret required)
  - Encrypted blob with wrong secret → still fails (regression)

- [ ] **20. Update `internal/infrastructure/wire/` handler tests**
  - Add test case: `GET /auth` with CIMD URL as `client_id` (mock CIMD fetch in mock service)
  - Verify `/token` exchange works with CIMD `client_id`

### Phase 7 — Documentation & Config Files

- [ ] **21. Write ADR to `tasks/decisions.md`**
  - Context: MCP draft spec mandates CIMD SHOULD, DCR MAY (backwards compat only)
  - Decision: implement CIMD as primary registration path; keep DCR for backwards compat
  - Consequences: no pre-reg endpoint needed; SSRF risk mitigated by allowlist + guard

- [ ] **22. Update `config.yaml` and `.env.example`**
  - Add commented CIMD section to `config.yaml`:
    ```yaml
    proxy:
      cimd_enabled: true
      cimd_allow_list: []      # empty = accept any HTTPS URL
      cimd_cache_max_age: 1h
    ```
  - Add `MCP_PROXY_CIMD_ENABLED` to `.env.example`

- [ ] **23. Update `CLAUDE.md` key packages section**
  - Note new `cimd.go` / `cimd_cache.go` and their responsibilities
  - Update API endpoints section if any new well-known paths are added

---

### Phase 8 — `private_key_jwt` Client Authentication (ChatGPT compatibility)

This phase is required to support ChatGPT as a client. ChatGPT uses
`token_endpoint_auth_method: "private_key_jwt"` and presents a signed RS256 JWT assertion
at the `/token` endpoint instead of a client secret.

- [ ] **24. Fetch and cache JWKS from CIMD `jwks_uri`** (`internal/service/auth/cimd.go`)
  - When a CIMD doc has `token_endpoint_auth_method: "private_key_jwt"`, parse `jwks_uri`
  - Apply same SSRF guard as for the CIMD document itself
  - Cache with HTTP cache headers; fallback TTL 1 hour

- [ ] **25. Implement `private_key_jwt` client assertion validation** (`internal/service/auth/impl.go`)
  - At `/token` endpoint: detect `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
  - Parse `client_assertion` JWT; validate `iss == sub == client_id`, `aud` is the token
    endpoint URL, `exp` not expired, `jti` not replayed (short-lived nonce store)
  - Verify signature using key fetched from `jwks_uri` (use same JWKS fetch/cache as Phase 1)
  - On success: treat as authenticated confidential client (no PKCE requirement, though
    PKCE is still allowed and encouraged)
  - On failure: return `invalid_client`

- [ ] **26. Update `AccessTokenRequest` types for client assertion** (`internal/service/auth/types.go`)
  - Add `ClientAssertionType string \`form:"client_assertion_type"\``
  - Add `ClientAssertion string \`form:"client_assertion"\``

- [ ] **27. JTI replay-protection store** (`internal/service/auth/jti_store.go`)
  - Simple in-memory `sync.Map` with expiry; prune on access
  - `Seen(jti string, exp time.Time) bool` — returns true if already seen, registers if not
  - Prevents token-assertion replay within the JWT's validity window

- [ ] **28. Unit tests for `private_key_jwt` validation**
  - Happy path: valid RS256 JWT assertion from ChatGPT-like client
  - Error: expired JWT assertion
  - Error: `iss != sub`
  - Error: `aud` does not match token endpoint
  - Error: replayed `jti`
  - Error: signature verification failure (wrong key)

### Phase 9 — Localhost Port Matching (Claude Code compatibility)

Claude Code's published CIMD doc has portless redirect URIs (`http://localhost/callback`)
but the actual callback server listens on a port (e.g. 3118). Strict exact-match rejects
these. Janus needs a configurable matching policy.

- [ ] **29. Add configurable `localhost_redirect_uri_match` policy** (`internal/service/auth/cimd.go`)
  - Values: `"exact"` (default, strict) | `"port_insensitive"` (for localhost-only URIs,
    ignore port in comparison)
  - Rule: `port_insensitive` only applies when both the registered URI and the requested
    URI have `localhost` or `127.0.0.1` as host; HTTPS/remote URIs always use exact match
  - Log a warning when port-insensitive match is used (security trade-off)

- [ ] **30. Add to config** (`internal/infrastructure/config/config.go`)
  - `CIMDLocalhostPortInsensitive bool \`mapstructure:"cimd_localhost_port_insensitive"\``
  - Default: `false` (strict); set to `true` to support Claude Code 2.1.80+ portless URIs

- [ ] **31. Unit tests for localhost port-insensitive matching**
  - `http://localhost/callback` registered, `http://localhost:3118/callback` requested → match when enabled
  - `http://localhost/callback` registered, `http://localhost:3118/callback` requested → reject when disabled
  - `https://example.com/callback` → always exact match regardless of config

---

## Non-Goals (deferred)

- **Keycloak `delegate` mode + CIMD**: In delegate mode, each MCP client gets a Keycloak
  registration. CIMD clients would need ephemeral Keycloak registrations. Deferred until
  there is a concrete use case.

- **Step-up authorization / incremental scope consent**: Spec section on runtime
  `insufficient_scope` 403 responses + scope accumulation. Partially satisfied by existing
  `WWW-Authenticate` header implementation; full step-up flow deferred.

---

## Completion Checklist

Before marking this epic done:
```
task build   # must compile cleanly
task test    # all tests pass
task lint    # no lint errors
```
