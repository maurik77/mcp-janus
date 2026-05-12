#!/usr/bin/env bash
# keycloak-setup.sh — idempotent Keycloak configuration for MCP proxy.
#
# Creates (or skips if already present):
#   • Realm            ${KC_REALM}
#   • Proxy client     ${KC_PROXY_CLIENT}  (direct-grant + PKCE enabled)
#   • Client scope     mcp:tools           (audience mapper → ${KC_AUDIENCE})
#   • Dev test user    ${KC_TEST_USER}
#   • DCR initial access token             (printed at the end)
#
# Environment variables (all have defaults):
#   KC_BASE          Keycloak base URL       default: http://localhost:8090
#   KC_REALM         Realm name              default: mcp
#   KC_ADMIN         Admin username          default: admin
#   KC_ADMIN_PASS    Admin password          default: admin
#   KC_PROXY_CLIENT  Proxy client ID         default: mcp-proxy-client
#   KC_PROXY_SECRET  Proxy client secret     default: mcp-proxy-secret
#   KC_AUDIENCE      Upstream resource URL   default: http://localhost:8081
#   KC_REDIRECT_URI  Proxy callback URL      default: http://localhost:8080/callback
#   KC_TEST_USER     Dev test username       default: devuser
#   KC_TEST_PASS     Dev test password       default: DevPass1!
#
# Requirements: curl, jq

set -uo pipefail

KC_BASE="${KC_BASE:-http://localhost:8090}"
KC_REALM="${KC_REALM:-mcp}"
KC_ADMIN="${KC_ADMIN:-admin}"
KC_ADMIN_PASS="${KC_ADMIN_PASS:-admin}"
KC_PROXY_CLIENT="${KC_PROXY_CLIENT:-mcp-proxy-client}"
KC_PROXY_SECRET="${KC_PROXY_SECRET:-mcp-proxy-secret}"
KC_AUDIENCE="${KC_AUDIENCE:-http://localhost:8081}"
KC_REDIRECT_URI="${KC_REDIRECT_URI:-http://localhost:8080/callback}"
KC_TEST_USER="${KC_TEST_USER:-devuser}"
KC_TEST_PASS="${KC_TEST_PASS:-DevPass1!}"

SCOPE_NAME="mcp:tools"
SCOPE_DISPLAY="MCP Tools"

# ─── Logging helpers ──────────────────────────────────────────────────────────

log()  { printf "  %s\n" "$*"; }
ok()   { printf "\033[32m✓\033[0m %s\n" "$*"; }
skip() { printf "\033[33m–\033[0m %s (already exists)\n" "$*"; }
fail() { printf "\033[31m✗\033[0m %s\n" "$*" >&2; exit 1; }
hdr()  { printf "\n\033[1m%s\033[0m\n" "$*"; }

# ─── Dependency check ─────────────────────────────────────────────────────────

for cmd in curl jq; do
  command -v "$cmd" >/dev/null 2>&1 || fail "Required command not found: $cmd"
done

# ─── HTTP helpers ─────────────────────────────────────────────────────────────

# admin_post <path> <token> <json-body>
# Returns HTTP status; body goes to stdout if not empty.
admin_post() {
  local path="$1" token="$2" body="$3"
  curl -s -o /tmp/kc_resp -w "%{http_code}" \
    -X POST "${KC_BASE}${path}" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d "${body}"
}

# admin_put <path> <token> [json-body]
admin_put() {
  local path="$1" token="$2" body="${3:-}"
  local args=(-s -o /tmp/kc_resp -w "%{http_code}" -X PUT "${KC_BASE}${path}"
              -H "Authorization: Bearer ${token}")
  if [ -n "$body" ]; then
    args+=(-H "Content-Type: application/json" -d "${body}")
  fi
  curl "${args[@]}"
}

# admin_get <path> <token>  — prints JSON body, returns 0 on 200.
admin_get() {
  local path="$1" token="$2"
  curl -sf "${KC_BASE}${path}" -H "Authorization: Bearer ${token}"
}

# expect <status> <desc> — reads status from stdin, fails if not expected.
# Accepts multiple expected codes: expect "201 409" "create X"
expect() {
  local expected="$1" desc="$2"
  local status
  read -r status
  if echo "$expected" | grep -qw "$status"; then
    if [ "$status" = "409" ] || [ "$status" = "200" ] && echo "$expected" | grep -qw "201"; then
      skip "$desc"
    else
      ok "$desc"
    fi
  else
    fail "$desc → unexpected HTTP $status: $(cat /tmp/kc_resp 2>/dev/null)"
  fi
}

# ─── Wait for Keycloak ────────────────────────────────────────────────────────

wait_for_keycloak() {
  hdr "Waiting for Keycloak at ${KC_BASE} ..."
  local attempts=0
  until curl -sf "${KC_BASE}/realms/master" >/dev/null 2>&1; do
    attempts=$((attempts + 1))
    if [ "$attempts" -ge 36 ]; then
      fail "Keycloak did not become ready after 180 s"
    fi
    printf "."
    sleep 5
  done
  printf "\n"
  ok "Keycloak is ready"
}

# ─── Admin token ──────────────────────────────────────────────────────────────

get_admin_token() {
  local token
  token=$(curl -sf \
    -X POST "${KC_BASE}/realms/master/protocol/openid-connect/token" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&client_id=admin-cli&username=${KC_ADMIN}&password=${KC_ADMIN_PASS}" \
    | jq -r '.access_token')
  [ -n "$token" ] && [ "$token" != "null" ] || fail "Could not obtain admin token"
  echo "$token"
}

# ─── Realm ────────────────────────────────────────────────────────────────────

create_realm() {
  hdr "Realm: ${KC_REALM}"
  admin_post "/admin/realms" "$1" \
    "$(jq -n --arg r "$KC_REALM" '{realm:$r, enabled:true, displayName:"MCP Proxy"}')" \
    | expect "201 409" "realm '${KC_REALM}'"
}

# ─── Proxy client ─────────────────────────────────────────────────────────────

create_proxy_client() {
  local token="$1"
  hdr "Client: ${KC_PROXY_CLIENT}"

  local payload
  payload=$(jq -n \
    --arg id   "$KC_PROXY_CLIENT" \
    --arg sec  "$KC_PROXY_SECRET" \
    --arg ruri "$KC_REDIRECT_URI" \
    '{
      clientId:                  $id,
      secret:                    $sec,
      enabled:                   true,
      publicClient:              false,
      directAccessGrantsEnabled: true,
      standardFlowEnabled:       true,
      redirectUris:              [$ruri],
      webOrigins:                ["+"],
      protocol:                  "openid-connect",
      attributes: {
        "pkce.code.challenge.method": "S256"
      }
    }')

  admin_post "/admin/realms/${KC_REALM}/clients" "$token" "$payload" \
    | expect "201 409" "client '${KC_PROXY_CLIENT}'"
}

# ─── Scope: mcp:tools ─────────────────────────────────────────────────────────

create_scope() {
  local token="$1"
  hdr "Scope: ${SCOPE_NAME}"

  # Create scope
  admin_post "/admin/realms/${KC_REALM}/client-scopes" "$token" \
    "$(jq -n \
        --arg n "$SCOPE_NAME" \
        --arg d "$SCOPE_DISPLAY" \
        '{name:$n, description:$d, protocol:"openid-connect",
          attributes:{"include.in.token.scope":"true","display.on.consent.screen":"true"}}')" \
    | expect "201 409" "scope '${SCOPE_NAME}'"

  # Look up its ID
  local scope_id
  scope_id=$(admin_get "/admin/realms/${KC_REALM}/client-scopes" "$token" \
    | jq -r --arg n "$SCOPE_NAME" '.[] | select(.name==$n) | .id')
  [ -n "$scope_id" ] || fail "scope '${SCOPE_NAME}' not found after creation"
  log "scope id: ${scope_id}"

  # Add audience mapper
  admin_post "/admin/realms/${KC_REALM}/client-scopes/${scope_id}/protocol-mappers/models" "$token" \
    "$(jq -n \
        --arg aud "$KC_AUDIENCE" \
        '{name:"aud-mapper", protocol:"openid-connect",
          protocolMapper:"oidc-audience-mapper", consentRequired:false,
          config:{
            "included.custom.audience": $aud,
            "access.token.claim":       "true",
            "id.token.claim":           "false"
          }}')" \
    | expect "201 409" "audience mapper → ${KC_AUDIENCE}"

  # Assign scope as optional to the proxy client
  local client_uuid
  client_uuid=$(admin_get \
    "/admin/realms/${KC_REALM}/clients?clientId=${KC_PROXY_CLIENT}" "$token" \
    | jq -r '.[0].id')
  [ -n "$client_uuid" ] && [ "$client_uuid" != "null" ] \
    || fail "proxy client '${KC_PROXY_CLIENT}' not found"

  local status
  status=$(admin_put \
    "/admin/realms/${KC_REALM}/clients/${client_uuid}/optional-client-scopes/${scope_id}" \
    "$token")
  if [ "$status" = "204" ] || [ "$status" = "409" ]; then
    ok "scope assigned to client"
  else
    fail "assign scope to client → HTTP $status"
  fi
}

# ─── Test user ────────────────────────────────────────────────────────────────

create_test_user() {
  local token="$1"
  hdr "Test user: ${KC_TEST_USER}"

  admin_post "/admin/realms/${KC_REALM}/users" "$token" \
    "$(jq -n --arg u "$KC_TEST_USER" '{username:$u, enabled:true}')" \
    | expect "201 409" "user '${KC_TEST_USER}'"

  # Set (or reset) password
  local user_id
  user_id=$(admin_get \
    "/admin/realms/${KC_REALM}/users?username=${KC_TEST_USER}" "$token" \
    | jq -r '.[0].id')
  [ -n "$user_id" ] && [ "$user_id" != "null" ] \
    || fail "user '${KC_TEST_USER}' not found"

  admin_put "/admin/realms/${KC_REALM}/users/${user_id}/reset-password" "$token" \
    "$(jq -n --arg p "$KC_TEST_PASS" '{type:"password", value:$p, temporary:false}')" \
    | expect "204" "password for '${KC_TEST_USER}'"
}

# ─── DCR initial access token ─────────────────────────────────────────────────

create_initial_token() {
  local token="$1"
  hdr "DCR initial access token"

  local resp
  resp=$(curl -sf \
    -X POST "${KC_BASE}/admin/realms/${KC_REALM}/clients-initial-access" \
    -H "Authorization: Bearer ${token}" \
    -H "Content-Type: application/json" \
    -d '{"expiration":86400,"count":100}')

  local iat
  iat=$(echo "$resp" | jq -r '.token')
  [ -n "$iat" ] && [ "$iat" != "null" ] || fail "Could not create initial access token"

  ok "DCR initial access token created"
  echo "$iat"   # returned to caller
}

# ─── Identity Provider federation (Azure AD B2C) ──────────────────────────────

configure_azure_idp() {
  local token="$1"
  hdr "Identity Provider: Azure AD B2C"

  # Create the OIDC Identity Provider
  admin_post "/admin/realms/${KC_REALM}/identity-provider/instances" "$token" \
    "$(jq -n \
        --arg cid  "$AZURE_CLIENT_ID" \
        --arg csec "$AZURE_CLIENT_SECRET" \
        --arg disc "$AZURE_OIDC_URL" \
        '{
          alias:                       "azure-b2c",
          displayName:                 "Azure AD B2C",
          providerId:                  "oidc",
          enabled:                     true,
          trustEmail:                  true,
          firstBrokerLoginFlowAlias:   "first broker login",
          config: {
            clientId:          $cid,
            clientSecret:      $csec,
            discoveryEndpoint: $disc,
            defaultScopes:     "openid profile email",
            syncMode:          "IMPORT"
          }
        }')" \
    | expect "201 409" "identity provider 'azure-b2c'"

  # Add attribute mappers for key claims
  for CLAIM in email name preferred_username upn; do
    admin_post \
      "/admin/realms/${KC_REALM}/identity-provider/instances/azure-b2c/mappers" "$token" \
      "$(jq -n \
          --arg claim "$CLAIM" \
          '{
            name:                     ("map-" + $claim),
            identityProviderMapper:   "oidc-user-attribute-idp-mapper",
            identityProviderAlias:    "azure-b2c",
            config: {
              claim:    $claim,
              attribute: $claim,
              syncMode: "INHERIT"
            }
          }')" \
      | expect "201 409" "claim mapper '${CLAIM}'"
  done

  # Add a protocol mapper on the proxy client to expose "upn" in Keycloak JWTs
  local client_uuid
  client_uuid=$(admin_get \
    "/admin/realms/${KC_REALM}/clients?clientId=${KC_PROXY_CLIENT}" "$token" \
    | jq -r '.[0].id')
  [ -n "$client_uuid" ] && [ "$client_uuid" != "null" ] \
    || fail "proxy client '${KC_PROXY_CLIENT}' not found"

  admin_post \
    "/admin/realms/${KC_REALM}/clients/${client_uuid}/protocol-mappers/models" "$token" \
    "$(jq -n '{
      name:           "upn-mapper",
      protocol:       "openid-connect",
      protocolMapper: "oidc-usermodel-attribute-mapper",
      config: {
        "user.attribute":      "upn",
        "claim.name":          "upn",
        "jsonType.label":      "String",
        "id.token.claim":      "true",
        "access.token.claim":  "true",
        "userinfo.token.claim":"true"
      }
    }')" \
    | expect "201 409" "protocol mapper 'upn' on proxy client"

  ok "Azure AD B2C identity provider configured"
}

# ─── Summary ──────────────────────────────────────────────────────────────────

print_summary() {
  local iat="$1"
  cat <<EOF

╔══════════════════════════════════════════════════════════════════════╗
║           Keycloak setup complete — add to config.yaml              ║
╚══════════════════════════════════════════════════════════════════════╝

idp:
  openid_configuration_url: ${KC_BASE}/realms/${KC_REALM}/.well-known/openid-configuration
  client_id: ${KC_PROXY_CLIENT}
  client_secret: ${KC_PROXY_SECRET}

  # Delegate MCP client registration to Keycloak (RFC 7591 DCR)
  registration_mode: delegate
  registration_initial_token: ${iat}

  # JWT validation
  validate_audience: true
  audience: ${KC_AUDIENCE}
  validate_issuer: true

  scopes:
    - openid
    - offline_access
    - mcp:tools

# Test user credentials (direct grant / dev only)
# username: ${KC_TEST_USER}
# password: ${KC_TEST_PASS}

# Admin console: ${KC_BASE}/admin/master/console/
# Realm console: ${KC_BASE}/admin/${KC_REALM}/console/
EOF
}

# ─── Main ─────────────────────────────────────────────────────────────────────

main() {
  wait_for_keycloak

  hdr "Authenticating as admin ..."
  TOKEN=$(get_admin_token)
  ok "Admin token obtained"

  create_realm        "$TOKEN"
  create_proxy_client "$TOKEN"
  create_scope        "$TOKEN"
  create_test_user    "$TOKEN"

  IAT=$(create_initial_token "$TOKEN")

  # Azure AD B2C federation (optional)
  AZURE_CLIENT_ID="${AZURE_CLIENT_ID:-}"
  if [ -n "$AZURE_CLIENT_ID" ]; then
    AZURE_CLIENT_SECRET="${AZURE_CLIENT_SECRET:-}"
    AZURE_OIDC_URL="${AZURE_OIDC_URL:-}"
    configure_azure_idp "$TOKEN"
  else
    log "AZURE_CLIENT_ID not set — skipping Identity Provider federation."
  fi

  print_summary "$IAT"
}

main
