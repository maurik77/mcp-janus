#!/usr/bin/env bash
# =============================================================================
# add-ngrok-redirect.sh  –  Add the ngrok redirect URI to the mcp-janus client
# =============================================================================
# Run this AFTER setup-keycloak.sh, once per Keycloak instance.
# Idempotent: safe to run multiple times.
#
# Usage:
#   ./scripts/keycloak/add-ngrok-redirect.sh
# =============================================================================

set -euo pipefail

KC_BASE="${KC_BASE:-http://localhost:8888}"
KC_ADMIN_USER="${KC_ADMIN_USER:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
REALM="mcp-dev"
CLIENT_ID="mcp-janus"
NGROK_DOMAIN="https://suboral-wiley-predesirously.ngrok-free.dev"
NGROK_REDIRECT="${NGROK_DOMAIN}/callback"

info() { echo "  ✓ $*"; }
die()  { echo "✗ ERROR: $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found."
}

require_cmd curl
require_cmd jq

echo "── Adding ngrok redirect URI to Keycloak client ─────────────────────"

# Get admin token
ADMIN_TOKEN=$(curl -sf -X POST \
  "$KC_BASE/realms/master/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=admin-cli" \
  -d "username=$KC_ADMIN_USER" \
  -d "password=$KC_ADMIN_PASS" \
  | jq -r '.access_token') || die "Failed to obtain admin token."
[[ "$ADMIN_TOKEN" != "null" && -n "$ADMIN_TOKEN" ]] || die "Admin token is null."

kc_admin() {
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

# Get client UUID
CLIENT_UUID=$(kc_admin GET "/realms/$REALM/clients?clientId=$CLIENT_ID" \
  | jq -r '.[0].id') || die "Could not find client '$CLIENT_ID'"
[[ -n "$CLIENT_UUID" && "$CLIENT_UUID" != "null" ]] \
  || die "Client '$CLIENT_ID' not found. Run setup-keycloak.sh first."
info "Client UUID: $CLIENT_UUID"

# Get current redirect URIs
CURRENT=$(kc_admin GET "/realms/$REALM/clients/$CLIENT_UUID" \
  | jq '.redirectUris')

# Check if ngrok redirect is already present
if echo "$CURRENT" | jq -e --arg u "$NGROK_REDIRECT" 'map(select(. == $u)) | length > 0' >/dev/null 2>&1; then
  info "Redirect URI already present: $NGROK_REDIRECT"
else
  # Add ngrok redirect URI and web origin
  UPDATED=$(echo "$CURRENT" | jq --arg u "$NGROK_REDIRECT" '. + [$u]')
  kc_admin PUT "/realms/$REALM/clients/$CLIENT_UUID" \
    "$(jq -n \
      --argjson ru "$UPDATED" \
      --arg origin "$NGROK_DOMAIN" \
      '{redirectUris: $ru, webOrigins: ["http://localhost:8080", $origin]}')" >/dev/null
  info "Added redirect URI: $NGROK_REDIRECT"
fi

echo
echo "  Client '$CLIENT_ID' now accepts:"
kc_admin GET "/realms/$REALM/clients/$CLIENT_UUID" | jq -r '.redirectUris[]' | sed 's/^/    /'
echo
