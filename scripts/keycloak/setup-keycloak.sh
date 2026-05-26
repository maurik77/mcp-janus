#!/usr/bin/env bash
# =============================================================================
# setup-keycloak.sh  –  Bootstrap a Keycloak dev realm for MCP Janus testing
# =============================================================================
# Prerequisites: curl, jq
# Keycloak must be running at http://localhost:8888 (see docker-compose.keycloak.yaml)
#
# What this script creates:
#   Realm    : mcp-dev
#   Client   : mcp-janus  (confidential, standard flow + offline_access)
#   User     : testuser / Password123!
#
# At the end it writes the resolved client secret to .env.keycloak-dev
# so you can `source .env.keycloak-dev` before running the proxy.
# =============================================================================

set -euo pipefail

KC_BASE="${KC_BASE:-http://localhost:8888}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="mcp-dev"
CLIENT_ID="mcp-janus"
TEST_USER="testuser"
TEST_PASS="Password123!"
TEST_EMAIL="testuser@example.com"
REDIRECT_URI="http://localhost:8080/callback"
ENV_OUT=".env.keycloak-dev"

# ─── helpers ──────────────────────────────────────────────────────────────────

info()    { echo "  ✓ $*"; }
section() { echo; echo "── $* ──────────────────────────────────────"; }
die()     { echo "✗ ERROR: $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found. Install it first."
}

# ─── pre-flight ───────────────────────────────────────────────────────────────

require_cmd curl
require_cmd jq

section "Waiting for Keycloak at $KC_BASE"
MAX_TRIES=30
for i in $(seq 1 "$MAX_TRIES"); do
  if curl -sf "$KC_BASE/health/ready" >/dev/null 2>&1; then
    info "Keycloak is ready (attempt $i/$MAX_TRIES)"
    break
  fi
  if [[ $i -eq $MAX_TRIES ]]; then
    die "Keycloak did not become ready after $MAX_TRIES attempts. Is it running?\n  docker compose -f docker-compose.keycloak.yaml up -d"
  fi
  echo "  waiting… ($i/$MAX_TRIES)"
  sleep 5
done

# ─── admin token ──────────────────────────────────────────────────────────────

section "Authenticating as Keycloak admin"
ADMIN_TOKEN=$(curl -sf -X POST \
  "$KC_BASE/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KC_ADMIN_USER" \
  -d "password=$KC_ADMIN_PASS" \
  | jq -r '.access_token') || die "Failed to obtain admin token. Check admin credentials."
[[ "$ADMIN_TOKEN" != "null" && -n "$ADMIN_TOKEN" ]] || die "Admin token is null."
info "Admin token obtained"

kc_admin() {
  # Usage: kc_admin <method> <path> [body]
  local method="$1" path="$2" body="${3:-}"
  local url="$KC_BASE/admin$path"
  if [[ -n "$body" ]]; then
    curl -sf -X "$method" "$url" \
      -H "Authorization: Bearer $ADMIN_TOKEN" \
      -H "Content-Type: application/json" \
      -d "$body"
  else
    curl -sf -X "$method" "$url" \
      -H "Authorization: Bearer $ADMIN_TOKEN"
  fi
}

# ─── realm ────────────────────────────────────────────────────────────────────

section "Creating realm '$REALM'"
EXISTING_REALM=$(kc_admin GET "/realms" | jq -r --arg r "$REALM" '.[] | select(.realm==$r) | .realm' 2>/dev/null || true)
if [[ "$EXISTING_REALM" == "$REALM" ]]; then
  info "Realm '$REALM' already exists – skipping creation"
else
  kc_admin POST "/realms" "$(jq -n \
    --arg realm "$REALM" \
    '{realm:$realm, enabled:true, displayName:"MCP Dev", registrationAllowed:false,
      accessTokenLifespan: 300, ssoSessionMaxLifespan: 86400}')" >/dev/null
  info "Realm '$REALM' created"
fi

# ─── client ───────────────────────────────────────────────────────────────────

section "Creating client '$CLIENT_ID'"
EXISTING_CLIENT=$(kc_admin GET "/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | jq -r '.[0].id' 2>/dev/null || true)

if [[ -n "$EXISTING_CLIENT" && "$EXISTING_CLIENT" != "null" ]]; then
  CLIENT_UUID="$EXISTING_CLIENT"
  info "Client '$CLIENT_ID' already exists (uuid: $CLIENT_UUID)"
else
  kc_admin POST "/realms/$REALM/clients" "$(jq -n \
    --arg cid "$CLIENT_ID" \
    --arg redir "$REDIRECT_URI" \
    '{
      clientId: $cid,
      name: "MCP Janus Proxy",
      description: "OAuth 2.1 proxy client for MCP Janus dev testing",
      enabled: true,
      publicClient: false,
      clientAuthenticatorType: "client-secret",
      standardFlowEnabled: true,
      directAccessGrantsEnabled: true,
      implicitFlowEnabled: false,
      serviceAccountsEnabled: false,
      redirectUris: [$redir],
      webOrigins: ["http://localhost:8080"],
      protocol: "openid-connect",
      defaultClientScopes: ["openid","profile","email"],
      optionalClientScopes: ["offline_access","address","phone"]
    }')" >/dev/null
  CLIENT_UUID=$(kc_admin GET "/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
  info "Client '$CLIENT_ID' created (uuid: $CLIENT_UUID)"
fi

# Retrieve (or regenerate) client secret
CLIENT_SECRET=$(kc_admin GET "/realms/$REALM/clients/$CLIENT_UUID/client-secret" \
  | jq -r '.value') || die "Could not retrieve client secret"
[[ -n "$CLIENT_SECRET" && "$CLIENT_SECRET" != "null" ]] \
  || die "Client secret is empty. The client may not be confidential."
info "Client secret retrieved"

# ─── test user ────────────────────────────────────────────────────────────────

section "Creating test user '$TEST_USER'"
EXISTING_USER=$(kc_admin GET "/realms/$REALM/users?username=$TEST_USER&exact=true" \
  | jq -r '.[0].id' 2>/dev/null || true)

if [[ -n "$EXISTING_USER" && "$EXISTING_USER" != "null" ]]; then
  USER_UUID="$EXISTING_USER"
  info "User '$TEST_USER' already exists (uuid: $USER_UUID) – resetting password"
else
  kc_admin POST "/realms/$REALM/users" "$(jq -n \
    --arg u "$TEST_USER" \
    --arg e "$TEST_EMAIL" \
    '{
      username: $u,
      email: $e,
      firstName: "Test",
      lastName: "User",
      enabled: true,
      emailVerified: true
    }')" >/dev/null
  USER_UUID=$(kc_admin GET "/realms/$REALM/users?username=$TEST_USER&exact=true" | jq -r '.[0].id')
  info "User '$TEST_USER' created (uuid: $USER_UUID)"
fi

# Set / reset password
kc_admin PUT "/realms/$REALM/users/$USER_UUID/reset-password" "$(jq -n \
  --arg p "$TEST_PASS" \
  '{type:"password", value:$p, temporary:false}')" >/dev/null
info "Password set for '$TEST_USER'"

# ─── write .env ───────────────────────────────────────────────────────────────

section "Writing $ENV_OUT"
cat >"$ENV_OUT" <<EOF
# Generated by scripts/keycloak/setup-keycloak.sh
# Source this file before starting the proxy:
#   source .env.keycloak-dev && CONFIG_PATH=. ./bin/mcpproxy

export MCP_IDP_CLIENT_SECRET="${CLIENT_SECRET}"
export CONFIG_PATH="."

# Handy shortcuts
export KC_BASE="${KC_BASE}"
export KC_REALM="${REALM}"
export KC_CLIENT_ID="${CLIENT_ID}"
export KC_TEST_USER="${TEST_USER}"
export KC_TEST_PASS="${TEST_PASS}"
EOF
info "Written to $ENV_OUT"

# ─── summary ──────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════"
echo "  Keycloak dev environment ready"
echo "════════════════════════════════════════════════════════════"
echo "  Admin console   : $KC_BASE"
echo "  Admin login     : $KC_ADMIN_USER / $KC_ADMIN_PASS"
echo "  Realm           : $REALM"
echo "  OIDC discovery  : $KC_BASE/realms/$REALM/.well-known/openid-configuration"
echo "  Client ID       : $CLIENT_ID"
echo "  Client secret   : $CLIENT_SECRET"
echo "  Test user       : $TEST_USER / $TEST_PASS"
echo "  Test user email : $TEST_EMAIL"
echo "════════════════════════════════════════════════════════════"
echo
echo "Next steps:"
echo
echo "  1. Copy config.keycloak-dev.yaml → config.yaml"
echo "     cp config.keycloak-dev.yaml config.yaml"
echo
echo "  2. Start the MCP test server (in another terminal):"
echo "     task run-testserver"
echo
echo "  3. Start the proxy with the Keycloak secret:"
echo "     source .env.keycloak-dev"
echo "     CONFIG_PATH=. ./bin/mcpproxy"
echo
echo "  4. Run the end-to-end test:"
echo "     source .env.keycloak-dev"
echo "     ./scripts/keycloak/test-proxy-flow.sh"
echo
