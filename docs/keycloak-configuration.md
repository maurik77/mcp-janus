# Keycloak Configuration Guide for MCP Janus

This guide covers all configuration needed on both the **Keycloak side** and the **MCP Janus side** to make the proxy work correctly with Keycloak as the Identity Provider.

---

## Overview

MCP Janus acts as an OAuth 2.1 proxy between MCP clients and a protected upstream MCP server. When integrated with Keycloak:

```
MCP Client → [opaque token] → MCP Janus (proxy) → [real Keycloak JWT] → Upstream MCP Server
                                       ↕
                               Keycloak (OAuth 2.1 / OIDC)
```

The proxy issues opaque AES-256-GCM encrypted tokens to clients. Internally it holds and validates the real Keycloak JWTs.

---

## Part 1 — Keycloak Side

### 1.1 Create a Realm

Create a dedicated realm for MCP (do not use the `master` realm in production).

- **Realm name**: e.g. `mcp-prod`
- **Enabled**: yes

### 1.2 Create the Proxy Client

This is the confidential OAuth client that MCP Janus uses to authenticate against Keycloak.

| Field | Value |
|---|---|
| Client ID | `mcp-proxy` (any name, must match `idp.client_id` in config) |
| Client authentication | ON (confidential client) |
| Authorization | OFF (not needed) |
| Authentication flow — Standard flow | ON |
| Authentication flow — Direct access grants | ON (needed only for testing/dev) |
| Valid redirect URIs | `https://<proxy-base-url>/callback` |
| Protocol | `openid-connect` |

After saving, go to **Credentials** tab and copy the client secret. This goes in `idp.client_secret`.

### 1.3 Create Client Scopes for the Upstream Resource

If the upstream MCP server requires audience validation, create a scope that adds the audience claim.

**Create a client scope:**

- **Name**: `mcp:tools` (or any meaningful scope name)
- **Protocol**: `openid-connect`
- **Include in token scope**: yes

**Add an Audience Protocol Mapper to the scope:**

- **Name**: `aud-mapper`
- **Mapper type**: `Audience`
- **Included custom audience**: `<upstream-resource-uri>` (e.g. `https://mcp-upstream.example.com`)
- **Add to access token**: ON
- **Add to ID token**: OFF

**Assign the scope to the proxy client:**

Go to the proxy client → **Client Scopes** tab → add the new scope as **Optional**.

The audience claim will only be included when the client explicitly requests this scope (e.g. `openid mcp:tools`).

### 1.4 Enable Dynamic Client Registration (DCR)

If you want MCP Janus to register MCP clients dynamically in Keycloak (`registration_mode: delegate`):

1. In the Keycloak Admin Console, go to **Realm Settings** → **Client Registration** tab.
2. Ensure **Client Registration Policies** allow anonymous or token-based registration, depending on your security model.

**Create an Initial Access Token** (recommended — restricts who can register clients):

1. Go to **Realm Settings** → **Client Registration** → **Initial Access Token** tab.
2. Click **Create**.
3. Set **Expiration** (e.g. `86400` seconds = 1 day).
4. Set **Count** (max number of client registrations allowed with this token).
5. Copy the generated token — this goes into `idp.registration_initial_token` (or the `MCP_IDP_REGISTRATION_INITIAL_TOKEN` env var).

> **Note**: If you leave `registration_initial_token` empty, Keycloak must be configured to allow unauthenticated DCR (trusted hosts policy). This is only suitable for trusted internal networks.

### 1.5 Configure Offline Access (Refresh Tokens)

For refresh token support, ensure the realm and proxy client allow offline access:

- The `offline_access` scope must be available in the realm (it is included by default in Keycloak).
- Add `offline_access` to the proxy client's default or optional scopes.
- Include `offline_access` in `idp.scopes` in MCP Janus config.

### 1.6 Create Users

Create the end users who will authenticate through MCP Janus:

1. Go to **Users** → **Add user**.
2. Set a username, enable the account.
3. Go to **Credentials** tab → set a password (turn off "Temporary" for non-dev).

---

## Part 2 — MCP Janus Side

### 2.1 Full `config.yaml` for Keycloak

```yaml
proxy:
  base_url: https://mcp-proxy.example.com   # Public URL of this proxy (used in OAuth redirect URIs)
  listen_addr: ":8080"
  log_level: info
  log_format: json

idp:
  # Keycloak client credentials (the proxy's own OAuth client)
  client_id: mcp-proxy
  client_secret: "<keycloak-client-secret>"   # Override via MCP_IDP_CLIENT_SECRET env var

  # Keycloak OIDC discovery endpoint for your realm
  openid_configuration_url: https://keycloak.example.com/realms/mcp-prod/.well-known/openid-configuration

  # Token TTL leeway for clock skew
  jwt_leeway: 60s

  # Scopes to request — include offline_access for refresh tokens
  scopes:
    - openid
    - offline_access
    - mcp:tools   # Include if you need audience claim in tokens

  # Claims from the Keycloak JWT to forward as HTTP headers to the upstream
  claims_mapping:
    sub: X-User-Sub
    preferred_username: X-Username
    email: X-Email
    name: X-Full-Name

  # ── Keycloak-specific settings ────────────────────────────────────────────

  # Delegate MCP client registration to Keycloak via RFC 7591 DCR.
  # "local"    — proxy manages clients itself (default)
  # "delegate" — proxy registers each MCP client in Keycloak via DCR
  registration_mode: delegate

  # Keycloak Initial Access Token for DCR (leave empty for unauthenticated DCR)
  # Override via MCP_IDP_REGISTRATION_INITIAL_TOKEN env var
  registration_initial_token: "<keycloak-initial-access-token>"

  # Validate the issuer claim in Keycloak JWTs (strongly recommended)
  # The expected issuer is taken automatically from the OIDC discovery document
  validate_issuer: true

  # Validate the audience claim in Keycloak JWTs
  # Set to true if you configure an audience mapper in Keycloak (see Part 1.3)
  validate_audience: true
  audience: https://mcp-upstream.example.com   # Must match the "Included custom audience" in Keycloak

  # Retry settings for fetching OIDC discovery / JWKS
  fetch_retry_attempts: 3
  fetch_retry_delay: 2s

encryption:
  # 32-byte (256-bit) key as 64 hex characters — used to encrypt opaque tokens
  # Generate with: openssl rand -hex 32
  master_key: "<64-hex-char-random-key>"

upstream:
  name: my-mcp-server
  resource: https://mcp-upstream.example.com   # Used as OAuth resource URI
  base_url: https://mcp-upstream.example.com   # Requests are forwarded here

telemetry:
  enabled: false   # Set to true to enable OpenTelemetry tracing + metrics
  service_name: mcp-proxy
  service_version: 1.0.0
  otlp_endpoint: localhost:4318
```

### 2.2 Environment Variable Overrides

Sensitive values should be injected via environment variables rather than hardcoded in `config.yaml`:

| Environment variable | Config key | Description |
|---|---|---|
| `MCP_IDP_CLIENT_SECRET` | `idp.client_secret` | Keycloak proxy client secret |
| `MCP_IDP_REGISTRATION_INITIAL_TOKEN` | `idp.registration_initial_token` | Keycloak DCR initial access token |
| `MCP_PROXY_BASE_URL` | `proxy.base_url` | Public base URL of the proxy |
| `MCP_LISTEN_ADDR` | `proxy.listen_addr` | Listen address (e.g. `:8443`) |
| `MCP_TLS` | `proxy.tls` | Enable TLS (`true`/`false`) |
| `MCP_TLS_CERT_FILE` | `proxy.tls_cert_file` | Path to TLS certificate |
| `MCP_TLS_KEY_FILE` | `proxy.tls_key_file` | Path to TLS key |
| `MCP_TELEMETRY_ENABLED` | `telemetry.enabled` | Enable telemetry |
| `MCP_TELEMETRY_OTLP_ENDPOINT` | `telemetry.otlp_endpoint` | OTLP collector endpoint |

### 2.3 OIDC Discovery URL Format

The `openid_configuration_url` must point to the Keycloak realm's OIDC discovery document:

```
https://<keycloak-host>/realms/<realm-name>/.well-known/openid-configuration
```

Example:
```
https://keycloak.example.com/realms/mcp-prod/.well-known/openid-configuration
```

MCP Janus fetches this URL at startup to discover the authorization endpoint, token endpoint, JWKS URI, and issuer.

### 2.4 Registration Modes

#### `local` (default)

The proxy manages client registrations internally. Client credentials are generated and encrypted locally. Nothing is registered in Keycloak. Use this when:
- You have a single, pre-configured Keycloak client for all MCP clients.
- You do not need per-MCP-client Keycloak clients.

#### `delegate`

Each time an MCP client calls `POST /register`, the proxy calls Keycloak's RFC 7591 DCR endpoint to create a corresponding client in Keycloak. The Keycloak-assigned `client_id` and `client_secret` are stored encrypted inside the opaque client ID blob returned to the MCP client. Use this when:
- You need per-client credentials and audit trails in Keycloak.
- You want full lifecycle management of MCP clients in Keycloak.

### 2.5 JWT Validation Settings

| Setting | Recommended value | Notes |
|---|---|---|
| `validate_issuer` | `true` | Rejects tokens from other realms or IdPs. Issuer is auto-discovered. |
| `validate_audience` | `true` | Rejects tokens not intended for your upstream resource. |
| `audience` | upstream resource URI | Must exactly match the audience configured in the Keycloak mapper. |
| `jwt_leeway` | `60s` | Allows up to 60 seconds of clock skew between proxy and Keycloak. |

> **Security note**: Always enable both `validate_issuer` and `validate_audience` in production to prevent token substitution attacks.

---

## Part 3 — Minimal Development Setup

For local development with Keycloak running on `localhost:9090`:

**Start Keycloak (Docker):**

```bash
docker run -p 9090:8080 \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
  -e KC_BOOTSTRAP_ADMIN_PASSWORD=admin \
  quay.io/keycloak/keycloak:26.0 start-dev
```

**Minimal `config.yaml` for dev:**

```yaml
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"
  log_level: debug
  log_format: json

idp:
  client_id: mcp-proxy
  client_secret: proxy-secret
  openid_configuration_url: http://localhost:9090/realms/mcp-dev/.well-known/openid-configuration
  jwt_leeway: 60s
  scopes:
    - openid
    - offline_access
  claims_mapping:
    sub: X-User-Sub
    preferred_username: X-Username

  registration_mode: delegate
  registration_initial_token: ""   # Empty = unauthenticated DCR (dev only)

  validate_issuer: true
  validate_audience: false          # Disable in dev if no audience mapper configured

encryption:
  master_key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

upstream:
  name: local-mcp-server
  resource: http://localhost:8081
  base_url: http://localhost:8081

telemetry:
  enabled: false
```

---

## Part 4 — Verification Checklist

### Keycloak
- [ ] Realm created and enabled
- [ ] Proxy client created (confidential, standard flow ON)
- [ ] Valid redirect URI includes `<proxy-base-url>/callback`
- [ ] Client secret copied to MCP Janus config
- [ ] `offline_access` scope assigned to proxy client (for refresh tokens)
- [ ] Audience mapper configured on a client scope (if `validate_audience: true`)
- [ ] Initial access token created (if `registration_mode: delegate`)
- [ ] Test user created and password set

### MCP Janus
- [ ] `idp.openid_configuration_url` points to correct Keycloak realm
- [ ] `idp.client_id` and `idp.client_secret` match the Keycloak proxy client
- [ ] `idp.registration_mode` set to `delegate` or `local` as needed
- [ ] `idp.validate_issuer: true` in production
- [ ] `idp.validate_audience: true` and `idp.audience` set in production
- [ ] `encryption.master_key` is a secure random 64-character hex string
- [ ] `upstream.base_url` and `upstream.resource` point to the upstream MCP server
- [ ] `proxy.base_url` matches the public URL (used in OAuth redirect URIs)
