#!/usr/bin/env bash
# =============================================================================
# verify-idp.sh  –  Verify Keycloak IdP connectivity without a browser
# =============================================================================
# Uses Keycloak's Direct Grant (Resource Owner Password Credentials) to obtain
# a token directly from Keycloak — useful for CI / quick sanity checks.
#
# Prerequisites: curl, jq
# Source .env.keycloak-dev first (or set the env vars manually).
# =============================================================================

set -euo pipefail

KC_BASE="${KC_BASE:-http://localhost:8888}"
KC_REALM="${KC_REALM:-mcp-dev}"
KC_CLIENT_ID="${KC_CLIENT_ID:-mcp-janus}"
MCP_IDP_CLIENT_SECRET="${MCP_IDP_CLIENT_SECRET:-}"
KC_TEST_USER="${KC_TEST_USER:-testuser}"
KC_TEST_PASS="${KC_TEST_PASS:-Password123!}"
PROXY="${PROXY:-http://localhost:8080}"

# ─── helpers ──────────────────────────────────────────────────────────────────

info()    { echo "  ✓ $*"; }
section() { echo; echo "── $* ──────────────────────────────────────"; }
fail()    { echo "  ✗ FAIL: $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' is required."
}

require_cmd curl
require_cmd jq

[[ -n "$MCP_IDP_CLIENT_SECRET" ]] \
  || fail "MCP_IDP_CLIENT_SECRET is not set. Run: source .env.keycloak-dev"

TOKEN_ENDPOINT="$KC_BASE/realms/$KC_REALM/protocol/openid-connect/token"

# ─── 1. OIDC discovery ────────────────────────────────────────────────────────

section "Fetching OIDC discovery document"
DISCO=$(curl -sf "$KC_BASE/realms/$KC_REALM/.well-known/openid-configuration") \
  || fail "Cannot reach Keycloak OIDC discovery at $KC_BASE"
ISSUER=$(echo "$DISCO" | jq -r '.issuer')
TOKEN_URL=$(echo "$DISCO" | jq -r '.token_endpoint')
JWKS_URI=$(echo "$DISCO" | jq -r '.jwks_uri')
info "Issuer       : $ISSUER"
info "Token URL    : $TOKEN_URL"
info "JWKS URI     : $JWKS_URI"

# ─── 2. JWKS reachable ────────────────────────────────────────────────────────

section "Checking JWKS endpoint"
KEY_COUNT=$(curl -sf "$JWKS_URI" | jq '.keys | length')
[[ "$KEY_COUNT" -gt 0 ]] || fail "JWKS is empty or unreachable"
info "JWKS keys    : $KEY_COUNT"

# ─── 3. Direct grant token request ───────────────────────────────────────────

section "Obtaining token via Direct Grant (password flow)"
echo "  NOTE: Direct Grant must be enabled on the client in Keycloak (it is by setup-keycloak.sh)"
TOKEN_RESP=$(curl -sf -X POST "$TOKEN_ENDPOINT" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=$KC_CLIENT_ID" \
  -d "client_secret=$MCP_IDP_CLIENT_SECRET" \
  -d "username=$KC_TEST_USER" \
  -d "password=$KC_TEST_PASS" \
  -d "scope=openid profile email offline_access") || fail "Direct grant failed. Is direct access grants enabled?"

ACCESS_TOKEN=$(echo "$TOKEN_RESP"  | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token')
ID_TOKEN=$(echo "$TOKEN_RESP"      | jq -r '.id_token')
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || fail "No access_token: $TOKEN_RESP"
info "Access token (truncated): ${ACCESS_TOKEN:0:40}…"
info "Refresh token (truncated): ${REFRESH_TOKEN:0:20}…"

# ─── 4. Decode & display JWT claims ──────────────────────────────────────────

section "Decoded access token claims"
# Decode base64url payload (middle part of JWT)
PAYLOAD=$(echo "$ACCESS_TOKEN" | cut -d. -f2 | python3 -c "
import sys, base64, json
data = sys.stdin.read().strip()
pad = 4 - len(data)%4
decoded = base64.urlsafe_b64decode(data + '='*pad)
print(json.dumps(json.loads(decoded), indent=2))
")
echo "$PAYLOAD" | jq '{sub, preferred_username, email, name, iss, exp, aud}'

# ─── 5. Check proxy health ────────────────────────────────────────────────────

section "Checking proxy health"
if curl -sf "$PROXY/health" >/dev/null 2>&1; then
  info "Proxy is reachable at $PROXY"
else
  echo "  ⚠ Proxy is not running at $PROXY (start it with: task run)"
  echo "    IdP verification still passed."
fi

# ─── 6. Check OIDC discovery via proxy ───────────────────────────────────────

section "Proxy OIDC discovery (proxy acting as AS)"
if curl -sf "$PROXY/.well-known/openid-configuration" >/dev/null 2>&1; then
  PROXY_DISCO=$(curl -sf "$PROXY/.well-known/openid-configuration")
  PROXY_ISSUER=$(echo "$PROXY_DISCO" | jq -r '.issuer')
  info "Proxy issuer : $PROXY_ISSUER"
else
  echo "  ⚠ Proxy OIDC discovery not available (proxy may not be running)"
fi

# ─── 7. Summary ───────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════"
echo "  ✓  Keycloak IdP is correctly configured for MCP Janus"
echo "════════════════════════════════════════════════════════════"
echo "  Realm     : $KC_REALM"
echo "  Client    : $KC_CLIENT_ID"
echo "  Test user : $KC_TEST_USER"
echo "  Token URL : $TOKEN_URL"
echo
