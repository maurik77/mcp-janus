# Keycloak Dev Setup Guide for MCP Janus

This guide explains how to run a local [Keycloak](https://www.keycloak.org/) instance and configure it as the Identity Provider (IdP) for MCP Janus development and testing.

---

## Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Quick Start (5 minutes)](#quick-start)
4. [Architecture](#architecture)
5. [Keycloak Setup Details](#keycloak-setup-details)
   - [Realm](#realm)
   - [Client](#client)
   - [Test User](#test-user)
   - [Scopes](#scopes)
6. [Proxy Configuration](#proxy-configuration)
7. [Testing the Integration](#testing-the-integration)
   - [Verify IdP connectivity (no browser)](#verify-idp-connectivity-no-browser)
   - [Full OAuth 2.1 flow (browser + PKCE)](#full-oauth-21-flow-browser--pkce)
   - [Manual curl walkthrough](#manual-curl-walkthrough)
8. [Keycloak Admin Console](#keycloak-admin-console)
9. [Troubleshooting](#troubleshooting)
10. [Keycloak Claims → Upstream Headers](#keycloak-claims--upstream-headers)
11. [Environment Variables Reference](#environment-variables-reference)

---

## Overview

MCP Janus acts as an OAuth 2.1 proxy. It does **not** implement its own login UI — it delegates authentication to a real IdP. In production this is Azure AD B2C, Okta, or any OIDC-compliant provider. For local development we use Keycloak.

```
MCP Client
    │  opaque bearer token (AES-256-GCM encrypted)
    ▼
MCP Janus proxy  (:8080)
    │  real Keycloak JWT
    ▼
Keycloak  (:8888)          ← issues / validates JWTs
    │  real JWT forwarded upstream
    ▼
MCP test server  (:8081)
```

---

## Prerequisites

| Tool | Version | Purpose |
|------|---------|---------|
| Docker + Docker Compose | any recent | Run Keycloak |
| `curl` | any | API calls |
| `jq` | ≥ 1.6 | JSON parsing in scripts |
| `python3` | ≥ 3.8 | PKCE generation, callback listener |
| Go / `task` | see root CLAUDE.md | Build the proxy |

Install `jq` if needed:
```bash
# macOS
brew install jq
# Ubuntu/Debian
apt-get install jq
```

---

## Quick Start

```bash
# 1. Start Keycloak + MCP test server
docker compose -f docker-compose.keycloak.yaml up -d

# 2. Configure Keycloak (realm, client, test user)
./scripts/keycloak/setup-keycloak.sh
#   → writes .env.keycloak-dev with the client secret

# 3. Copy Keycloak config over the default
cp config.keycloak-dev.yaml config.yaml

# 4. Build the proxy
task build

# 5. Start the proxy with the generated secret
source .env.keycloak-dev
CONFIG_PATH=. ./bin/mcpproxy

# 6. (new terminal) Start the MCP test server
task run-testserver

# 7. Verify the IdP connection (no browser needed)
source .env.keycloak-dev
./scripts/keycloak/verify-idp.sh

# 8. Run the full end-to-end OAuth flow
./scripts/keycloak/test-proxy-flow.sh
```

---

## Architecture

```
docker-compose.keycloak.yaml
├── keycloak-dev   (port 8888, realm: mcp-dev)
└── mcp-test-server (port 8081)

Local processes (not in Docker)
├── mcpproxy  (port 8080)  ← config.keycloak-dev.yaml
└── (browser for OAuth login)
```

The proxy runs locally so you can edit code and restart quickly without rebuilding Docker images. Keycloak runs in Docker because it is heavy to install natively.

---

## Keycloak Setup Details

The `setup-keycloak.sh` script automates all of the following via the Keycloak Admin REST API. This section explains what it creates so you can verify or adjust it via the Admin Console.

### Realm

| Setting | Value |
|---------|-------|
| Realm name | `mcp-dev` |
| Display name | MCP Dev |
| Registration allowed | false |
| Access token lifespan | 5 min (300 s) |
| SSO session max | 24 h |

Navigate to: **Admin console → Realm selector → mcp-dev**

### Client

| Setting | Value | Notes |
|---------|-------|-------|
| Client ID | `mcp-janus` | The value in `config.yaml → idp.client_id` |
| Client type | Confidential | Has a client secret |
| Standard flow | ✅ Enabled | Authorization code flow |
| Direct access grants | ✅ Enabled | Allows password flow for testing/CI |
| Valid redirect URIs | `http://localhost:8080/callback` | The proxy callback endpoint |
| Web origins | `http://localhost:8080` | |
| Client scopes (default) | openid, profile, email | |
| Client scopes (optional) | offline_access | Enables refresh tokens |

> **About offline_access:** Keycloak treats `offline_access` as an optional scope. MCP Janus requests it via the `scope` parameter to obtain a refresh token. The setup script adds it to the client's optional scopes.

Navigate to: **Admin console → mcp-dev realm → Clients → mcp-janus**

### Test User

| Setting | Value |
|---------|-------|
| Username | `testuser` |
| Password | `Password123!` |
| Email | `testuser@example.com` |
| First name | Test |
| Last name | User |
| Email verified | true |

Navigate to: **Admin console → mcp-dev realm → Users → testuser**

### Scopes

Keycloak emits the following claims in the access JWT when `openid profile email offline_access` is requested:

| Claim | Value (for testuser) | Mapped to header |
|-------|---------------------|-----------------|
| `sub` | UUID | `X-User-Sub` |
| `preferred_username` | `testuser` | `X-User-Username` |
| `name` | `Test User` | `X-User-Full-Name` |
| `email` | `testuser@example.com` | `X-User-Email` |

---

## Proxy Configuration

`config.keycloak-dev.yaml` is a ready-to-use proxy config. Copy it over `config.yaml`:

```bash
cp config.keycloak-dev.yaml config.yaml
```

Key settings explained:

```yaml
idp:
  client_id: mcp-janus          # must match Keycloak client ID
  client_secret: CHANGE_ME      # set via MCP_IDP_CLIENT_SECRET env var
  openid_configuration_url: http://localhost:8888/realms/mcp-dev/.well-known/openid-configuration
  jwt_leeway: 30s               # tolerance for clock skew
  scopes:
    - openid
    - profile
    - email
    - offline_access            # get refresh tokens from Keycloak
  claims_mapping:
    sub: X-User-Sub             # JWT claim → upstream HTTP header
    name: X-User-Full-Name
    email: X-User-Email
    preferred_username: X-User-Username
```

The `client_secret` is generated by Keycloak and printed by `setup-keycloak.sh`. **Never hardcode it.** Always pass it via the environment:

```bash
export MCP_IDP_CLIENT_SECRET="<secret from setup script>"
CONFIG_PATH=. ./bin/mcpproxy
```

### Encryption key

The `encryption.master_key` in the dev config is a placeholder. For any environment beyond local dev, generate a real key:

```bash
openssl rand -hex 32
```

---

## Testing the Integration

### Verify IdP connectivity (no browser)

`verify-idp.sh` uses Keycloak's Direct Grant (password flow) to obtain a real JWT — no browser required. It also checks JWKS and the proxy's OIDC discovery endpoint.

```bash
source .env.keycloak-dev
./scripts/keycloak/verify-idp.sh
```

Expected output:
```
── Fetching OIDC discovery document ────────────────────
  ✓ Issuer       : http://localhost:8888/realms/mcp-dev
  ✓ Token URL    : http://localhost:8888/realms/mcp-dev/protocol/openid-connect/token
  ✓ JWKS URI     : http://localhost:8888/realms/mcp-dev/protocol/openid-connect/certs

── Checking JWKS endpoint ──────────────────────────────
  ✓ JWKS keys    : 1

── Obtaining token via Direct Grant (password flow) ────
  ✓ Access token (truncated): eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9…
  ✓ Refresh token (truncated): eyJhbGciOiJIUzUxMiIsIn…

── Decoded access token claims ─────────────────────────
{
  "sub": "…uuid…",
  "preferred_username": "testuser",
  "email": "testuser@example.com",
  "name": "Test User",
  "iss": "http://localhost:8888/realms/mcp-dev",
  "exp": …,
  "aud": "account"
}
```

### Full OAuth 2.1 flow (browser + PKCE)

`test-proxy-flow.sh` exercises the complete proxy flow:

1. **DCR** — registers an ephemeral client with the proxy (`POST /register`)
2. **PKCE setup** — generates `code_verifier` / `code_challenge` locally
3. **Auth redirect** — opens browser at `GET /auth` → Keycloak login page
4. **Callback listener** — starts a local Python HTTP server on port 3000
5. **Code exchange** — `POST /token` with `code_verifier`
6. **MCP call** — `POST /mcp` with opaque bearer token
7. **Weather tool** — calls `tools/call` for `get_weather`
8. **Token refresh** — `POST /refresh` with opaque refresh token

```bash
source .env.keycloak-dev
./scripts/keycloak/test-proxy-flow.sh
```

The script opens your default browser. Log in as:
- Username: `testuser`
- Password: `Password123!`

### Manual curl walkthrough

If you prefer step-by-step manual testing:

#### Step 1 — Register a proxy client

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "client_name": "my-test-client",
    "redirect_uris": ["http://localhost:3000/callback"],
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"]
  }'
```

Save `client_id` and `client_secret` from the response.

#### Step 2 — Generate PKCE challenge

```bash
CODE_VERIFIER=$(python3 -c "
import base64, os
print(base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode())
")
CODE_CHALLENGE=$(python3 -c "
import base64, hashlib, sys
v = sys.argv[1].encode()
print(base64.urlsafe_b64encode(hashlib.sha256(v).digest()).rstrip(b'=').decode())
" "$CODE_VERIFIER")
echo "verifier : $CODE_VERIFIER"
echo "challenge: $CODE_CHALLENGE"
```

#### Step 3 — Open auth URL in browser

```bash
# Replace CLIENT_ID and CODE_CHALLENGE
open "http://localhost:8080/auth?\
response_type=code\
&client_id=<CLIENT_ID>\
&redirect_uri=http://localhost:3000/callback\
&state=manual-test\
&code_challenge=<CODE_CHALLENGE>\
&code_challenge_method=S256\
&resource=http://localhost:8081"
```

After login, Keycloak redirects to `http://localhost:3000/callback?code=<CODE>&state=…`

Copy the `code` value from the URL.

#### Step 4 — Exchange code for tokens

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=<CODE>" \
  -d "client_id=<CLIENT_ID>" \
  -d "client_secret=<CLIENT_SECRET>" \
  -d "redirect_uri=http://localhost:3000/callback" \
  -d "code_verifier=<CODE_VERIFIER>"
```

Save the `access_token` and `refresh_token`.

#### Step 5 — Call MCP through the proxy

```bash
# List tools
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'

# Call get_weather
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer <ACCESS_TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "id": 2,
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {"city": "Rome", "date": "2025-06-01"}
    }
  }'
```

#### Step 6 — Refresh the token

```bash
curl -X POST http://localhost:8080/refresh \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "refresh_token=<REFRESH_TOKEN>"
```

---

## Keycloak Admin Console

The Admin Console is at **http://localhost:8888** — login with `admin` / `admin`.

Useful pages:
- **Realm settings** → Sessions tab → adjust token lifespans
- **Clients → mcp-janus → Credentials** → view / regenerate the client secret
- **Users → testuser → Credentials** → reset password
- **Events** → track login events and errors
- **Sessions** → see active sessions

### Regenerate the client secret

If you need a new client secret:
```bash
# Via Admin API
source .env.keycloak-dev
CLIENT_UUID=$(curl -sf \
  "http://localhost:8888/admin/realms/mcp-dev/clients?clientId=mcp-janus" \
  -H "Authorization: Bearer $(curl -sf -X POST \
    'http://localhost:8888/realms/master/protocol/openid-connect/token' \
    -d 'grant_type=password&client_id=admin-cli&username=admin&password=admin' \
    | jq -r .access_token)" \
  | jq -r '.[0].id')
echo "Client UUID: $CLIENT_UUID"
# Then in Admin Console: Clients → mcp-janus → Credentials → Regenerate
```

Or just re-run `setup-keycloak.sh` — it is idempotent and will print the current secret.

---

## Troubleshooting

### "Failed to fetch OpenID configuration"

The proxy cannot reach Keycloak on startup.

```bash
# Check Keycloak is healthy
curl http://localhost:8888/health/ready

# Check the discovery endpoint
curl http://localhost:8888/realms/mcp-dev/.well-known/openid-configuration | jq .issuer

# Check proxy config points to the right URL
grep openid_configuration_url config.yaml
```

### "Client authentication failed" / 401 on /token

The client secret in `config.yaml` does not match Keycloak.

```bash
# Print the current Keycloak client secret
source .env.keycloak-dev
./scripts/keycloak/setup-keycloak.sh   # re-runs idempotently, prints secret
# Then update MCP_IDP_CLIENT_SECRET and restart the proxy
```

### "JWT validation failed" in proxy logs

The proxy decrypts the opaque token but Keycloak's JWT fails validation.

**Check JWKS:**
```bash
curl http://localhost:8888/realms/mcp-dev/protocol/openid-connect/certs | jq .
```

**Check clock skew:** The default `jwt_leeway` is 30 s. If your system clock differs from the container clock by more, increase it in `config.yaml`:
```yaml
idp:
  jwt_leeway: 60s
```

**Check token expiry:** Default Keycloak access tokens expire in 5 minutes. Test quickly after login or use the refresh flow.

### Browser doesn't open for the OAuth flow

Paste the printed URL manually into your browser. Or use `verify-idp.sh` which doesn't need a browser.

### Keycloak container takes too long to start

On first run, Keycloak needs ~45–60 seconds. `setup-keycloak.sh` waits up to 150 seconds (30 × 5 s intervals). If it times out:

```bash
# Check container logs
docker logs keycloak-dev

# Check health manually
curl http://localhost:8888/health/ready
```

### "offline_access scope not available"

Direct grant calls may omit the `offline_access` scope if it wasn't added to the client's optional scopes. Re-run `setup-keycloak.sh` — it configures this automatically.

---

## Keycloak Claims → Upstream Headers

When a request reaches the upstream MCP server, the proxy injects these headers (from `claims_mapping` in `config.keycloak-dev.yaml`):

| Keycloak JWT claim | Upstream HTTP header | Example value |
|--------------------|---------------------|---------------|
| `sub` | `X-User-Sub` | `3f8a1b…` (UUID) |
| `name` | `X-User-Full-Name` | `Test User` |
| `email` | `X-User-Email` | `testuser@example.com` |
| `preferred_username` | `X-User-Username` | `testuser` |

The mapping is configurable in `config.yaml` under `idp.claims_mapping`. Any top-level JWT claim can be mapped to any header name.

---

## Environment Variables Reference

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_IDP_CLIENT_SECRET` | Keycloak client secret (**required**) | — |
| `CONFIG_PATH` | Directory containing `config.yaml` | `.` |
| `MCP_PROXY_BASE_URL` | Override `proxy.base_url` | from config |
| `MCP_LISTEN_ADDR` | Override `proxy.listen_addr` | `:8080` |
| `MCP_IDP_SKIP_TLS_VERIFY` | Skip TLS cert verification | `false` |
| `MCP_TELEMETRY_ENABLED` | Enable OpenTelemetry | from config |
| `MCP_ENCRYPTION_MASTER_KEY` | Override AES-256 master key | from config |
| `KC_BASE` | Keycloak base URL (scripts) | `http://localhost:8888` |
| `KC_REALM` | Keycloak realm (scripts) | `mcp-dev` |
| `KC_TEST_USER` | Test user login (scripts) | `testuser` |
| `KC_TEST_PASS` | Test user password (scripts) | `Password123!` |

---

## Files Created by This Setup

```
docker-compose.keycloak.yaml     ← Keycloak + MCP test server
config.keycloak-dev.yaml         ← Proxy config for Keycloak
.env.keycloak-dev                ← Generated by setup script (gitignored)
scripts/keycloak/
  setup-keycloak.sh              ← One-shot Keycloak bootstrap
  verify-idp.sh                  ← Sanity check (no browser needed)
  test-proxy-flow.sh             ← Full E2E test with browser + PKCE
```

`.env.keycloak-dev` contains the Keycloak client secret — it is in `.gitignore` and must not be committed.
