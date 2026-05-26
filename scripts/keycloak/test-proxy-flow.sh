#!/usr/bin/env bash
# =============================================================================
# test-proxy-flow.sh  –  End-to-end OAuth 2.1 + PKCE flow test for MCP Janus
# =============================================================================
# Prerequisites: curl, jq, python3  (python3 is used for the callback listener
#                and PKCE code_challenge generation)
#
# Required env vars (set by sourcing .env.keycloak-dev):
#   MCP_IDP_CLIENT_SECRET   – Keycloak client secret
#   KC_TEST_USER            – test user login
#   KC_TEST_PASS            – test user password
#
# The proxy must be running at http://localhost:8080 (task run or ./bin/mcpproxy)
# The MCP test server must be running at http://localhost:8081 (task run-testserver)
# =============================================================================

set -euo pipefail

PROXY="${PROXY:-http://localhost:8080}"
CALLBACK_PORT="${CALLBACK_PORT:-3000}"
CALLBACK_URI="http://localhost:${CALLBACK_PORT}/callback"
KC_BASE="${KC_BASE:-http://localhost:8888}"
KC_REALM="${KC_REALM:-mcp-dev}"
KC_CLIENT_ID="${KC_CLIENT_ID:-mcp-janus}"
KC_TEST_USER="${KC_TEST_USER:-testuser}"
KC_TEST_PASS="${KC_TEST_PASS:-Password123!}"
MCP_RESOURCE="${MCP_RESOURCE:-http://localhost:8081}"

# ─── helpers ──────────────────────────────────────────────────────────────────

info()    { echo "  ✓ $*"; }
section() { echo; echo "── $* ──────────────────────────────────────"; }
fail()    { echo "  ✗ FAIL: $*" >&2; exit 1; }

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || fail "'$1' is required. Install it first."
}

require_cmd curl
require_cmd jq
require_cmd python3

# ─── 0. health checks ─────────────────────────────────────────────────────────

section "Health checks"
curl -sf "$PROXY/health" >/dev/null || fail "Proxy not reachable at $PROXY. Run: task run"
info "Proxy is up"
curl -sf "http://localhost:8081/health" >/dev/null || fail "MCP test server not reachable. Run: task run-testserver"
info "MCP test server is up"

# ─── 1. PKCE setup ────────────────────────────────────────────────────────────

section "Generating PKCE parameters"
read -r CODE_VERIFIER CODE_CHALLENGE < <(python3 - <<'PYEOF'
import base64, hashlib, os, sys
verifier = base64.urlsafe_b64encode(os.urandom(40)).rstrip(b'=').decode()
challenge = base64.urlsafe_b64encode(
    hashlib.sha256(verifier.encode()).digest()
).rstrip(b'=').decode()
print(verifier, challenge)
PYEOF
)
STATE="test-$(python3 -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(8)).decode().rstrip("="))')"
info "code_verifier  : ${CODE_VERIFIER:0:20}…"
info "code_challenge : ${CODE_CHALLENGE:0:20}…"
info "state          : $STATE"

# ─── 2. Dynamic client registration ───────────────────────────────────────────

section "Registering a client with the proxy (RFC 7591 DCR)"
REG_RESP=$(curl -sf -X POST "$PROXY/register" \
  -H "Content-Type: application/json" \
  -d "$(jq -n \
    --arg cb "$CALLBACK_URI" \
    '{
      client_name: "mcp-janus-test-client",
      redirect_uris: [$cb],
      grant_types: ["authorization_code","refresh_token"],
      response_types: ["code"]
    }')")
CLIENT_ID=$(echo "$REG_RESP" | jq -r '.client_id')
CLIENT_SECRET=$(echo "$REG_RESP" | jq -r '.client_secret')
[[ -n "$CLIENT_ID" && "$CLIENT_ID" != "null" ]] || fail "DCR failed: $REG_RESP"
info "client_id      : ${CLIENT_ID:0:30}…"
info "client_secret  : ${CLIENT_SECRET:0:16}…"

# ─── 3. Start callback listener ───────────────────────────────────────────────

section "Starting callback listener on port $CALLBACK_PORT"
CALLBACK_RESULT_FILE=$(mktemp)
python3 - "$CALLBACK_PORT" "$CALLBACK_RESULT_FILE" &
LISTENER_PID=$!
sleep 0.5   # let the server bind

python3 - <<PYEOF &
import http.server, urllib.parse, sys, json

port = int("$CALLBACK_PORT")
result_file = "$CALLBACK_RESULT_FILE"

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        data = {k: v[0] for k, v in params.items()}
        with open(result_file, 'w') as f:
            json.dump(data, f)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.end_headers()
        self.wfile.write(b'''<html><body>
<h2>&#x2714; Authorization complete</h2>
<p>You can close this window and return to the terminal.</p>
</body></html>''')
    def log_message(self, *args): pass  # silence access log

httpd = http.server.HTTPServer(('localhost', port), Handler)
httpd.handle_request()  # handle exactly one request then exit
PYEOF
LISTENER_PID=$!
sleep 0.8

info "Listener running (PID $LISTENER_PID)"

# ─── 4. Build auth URL and open browser ───────────────────────────────────────

section "Starting OAuth 2.1 authorization flow"
AUTH_URL="$PROXY/auth?response_type=code\
&client_id=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$CLIENT_ID")\
&redirect_uri=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$CALLBACK_URI")\
&state=$STATE\
&code_challenge=$CODE_CHALLENGE\
&code_challenge_method=S256\
&resource=$(python3 -c "import urllib.parse,sys; print(urllib.parse.quote(sys.argv[1]))" "$MCP_RESOURCE")"

echo
echo "  Opening browser for Keycloak login…"
echo "  User: $KC_TEST_USER   Password: $KC_TEST_PASS"
echo
echo "  If the browser does not open automatically, paste this URL:"
echo "  $AUTH_URL"
echo

# Try to open browser (works on macOS and most Linux desktops)
if command -v open >/dev/null 2>&1; then
  open "$AUTH_URL" 2>/dev/null || true
elif command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$AUTH_URL" 2>/dev/null || true
fi

# Wait up to 120 s for the callback
echo "  Waiting for browser callback (up to 120 s)…"
for i in $(seq 1 120); do
  if [[ -s "$CALLBACK_RESULT_FILE" ]]; then break; fi
  sleep 1
done

wait "$LISTENER_PID" 2>/dev/null || true

[[ -s "$CALLBACK_RESULT_FILE" ]] || fail "No callback received within 120 s"
CALLBACK_PARAMS=$(cat "$CALLBACK_RESULT_FILE")
rm -f "$CALLBACK_RESULT_FILE"

AUTH_CODE=$(echo "$CALLBACK_PARAMS" | jq -r '.code')
RETURNED_STATE=$(echo "$CALLBACK_PARAMS" | jq -r '.state')
[[ -n "$AUTH_CODE" && "$AUTH_CODE" != "null" ]] || fail "No code in callback: $CALLBACK_PARAMS"
info "Authorization code received: ${AUTH_CODE:0:20}…"
info "State match: $([[ "$RETURNED_STATE" == "$STATE" ]] && echo 'OK' || echo "MISMATCH (got: $RETURNED_STATE)")"

# ─── 5. Token exchange ────────────────────────────────────────────────────────

section "Exchanging code for tokens (POST /token)"
TOKEN_RESP=$(curl -sf -X POST "$PROXY/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=authorization_code" \
  --data-urlencode "code=$AUTH_CODE" \
  --data-urlencode "client_id=$CLIENT_ID" \
  --data-urlencode "client_secret=$CLIENT_SECRET" \
  --data-urlencode "redirect_uri=$CALLBACK_URI" \
  --data-urlencode "code_verifier=$CODE_VERIFIER") || fail "Token exchange failed"

ACCESS_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.access_token')
REFRESH_TOKEN=$(echo "$TOKEN_RESP" | jq -r '.refresh_token')
[[ -n "$ACCESS_TOKEN" && "$ACCESS_TOKEN" != "null" ]] || fail "No access_token: $TOKEN_RESP"
info "Opaque access token : ${ACCESS_TOKEN:0:30}…"
info "Opaque refresh token: ${REFRESH_TOKEN:0:30}…"

# ─── 6. Call MCP through proxy ────────────────────────────────────────────────

section "Calling MCP proxy endpoint (tools/list)"
MCP_RESP=$(curl -sf -X POST "$PROXY/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}') || fail "MCP call failed (check proxy logs)"
info "MCP response:"
echo "$MCP_RESP" | jq . 2>/dev/null || echo "$MCP_RESP"

# ─── 7. Call a MCP tool ───────────────────────────────────────────────────────

section "Calling get_weather tool through proxy"
WEATHER_RESP=$(curl -sf -X POST "$PROXY/mcp" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"get_weather","arguments":{"city":"Rome","date":"2025-06-01"}}}') || fail "MCP tool call failed"
info "Weather response:"
echo "$WEATHER_RESP" | jq . 2>/dev/null || echo "$WEATHER_RESP"

# ─── 8. Token refresh ─────────────────────────────────────────────────────────

section "Testing token refresh (POST /refresh)"
REFRESH_RESP=$(curl -sf -X POST "$PROXY/refresh" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "grant_type=refresh_token" \
  --data-urlencode "refresh_token=$REFRESH_TOKEN") || fail "Refresh failed"
NEW_ACCESS=$(echo "$REFRESH_RESP" | jq -r '.access_token')
[[ -n "$NEW_ACCESS" && "$NEW_ACCESS" != "null" ]] || fail "No new access_token: $REFRESH_RESP"
info "New access token    : ${NEW_ACCESS:0:30}…"

# ─── 9. Summary ───────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════"
echo "  ✓  All steps passed — MCP Janus + Keycloak flow works!"
echo "════════════════════════════════════════════════════════════"
echo
