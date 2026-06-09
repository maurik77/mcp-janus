#!/usr/bin/env bash
# =============================================================================
# demo-start.sh  –  Start the full MCP Janus demo stack for GIF recording
# =============================================================================
# Prerequisites:
#   - Docker running
#   - ngrok configured with static domain suboral-wiley-predesirously.ngrok-free.dev
#   - task (Taskfile.dev) installed
#
# Run this script from the project root.
# Each component opens in a new Terminal tab (macOS only).
# =============================================================================

set -euo pipefail

NGROK_DOMAIN="suboral-wiley-predesirously.ngrok-free.dev"
NGROK_URL="https://${NGROK_DOMAIN}"

info()    { echo "  ✓ $*"; }
section() { echo; echo "── $* ──────────────────────────────────────"; }
die()     { echo "✗ ERROR: $*" >&2; exit 1; }

cd "$(dirname "$0")/.."
PROJECT_ROOT="$(pwd)"

# Restore config.yaml on exit
cleanup() {
  if [[ -f "config.yaml.demo-bak" ]]; then
    mv config.yaml.demo-bak config.yaml
    echo "  ✓ config.yaml restored"
  fi
}
trap cleanup EXIT

# ─── Step 1: build binaries ───────────────────────────────────────────────────

section "Building binaries"
task build
task build-testserver
info "Binaries ready"

# ─── Step 2: Keycloak ─────────────────────────────────────────────────────────

section "Starting Keycloak"
docker compose -f docker-compose.keycloak.yaml up -d
info "Keycloak starting on http://localhost:8888"

section "Waiting for Keycloak to be ready"
MAX_TRIES=30
for i in $(seq 1 "$MAX_TRIES"); do
  if curl -sf "http://localhost:8888/realms/master" >/dev/null 2>&1; then
    info "Keycloak ready (attempt $i/$MAX_TRIES)"
    break
  fi
  if [[ $i -eq $MAX_TRIES ]]; then
    die "Keycloak not ready after $MAX_TRIES attempts"
  fi
  echo "  waiting… ($i/$MAX_TRIES)"
  sleep 5
done

section "Configuring Keycloak realm"
./scripts/keycloak/setup-keycloak.sh
./scripts/keycloak/add-ngrok-redirect.sh
info "Keycloak configured"

# ─── Step 3: Source env and apply demo config ─────────────────────────────────

source .env.keycloak-dev
info "Loaded client secret from .env.keycloak-dev"

# Back up current config.yaml and use demo config
[[ -f "config.yaml" ]] && cp config.yaml config.yaml.demo-bak
cp config.demo.yaml config.yaml
# Inject the actual client secret into the active config
MCP_IDP_CLIENT_SECRET="${MCP_IDP_CLIENT_SECRET:-}"
info "Demo config activated (config.demo.yaml → config.yaml)"

# ─── Step 4: start components in separate Terminal tabs ───────────────────────

section "Starting MCP server (tab 1)"
osascript -e "
  tell application \"Terminal\"
    activate
    tell application \"System Events\" to keystroke \"t\" using command down
    delay 0.5
    do script \"cd '$PROJECT_ROOT' && ./bin/mcpserver\" in front window
  end tell"

sleep 1

section "Starting MCP Janus proxy (tab 2)"
osascript -e "
  tell application \"Terminal\"
    activate
    tell application \"System Events\" to keystroke \"t\" using command down
    delay 0.5
    do script \"cd '$PROJECT_ROOT' && source .env.keycloak-dev && CONFIG_PATH=. ./bin/mcpproxy\" in front window
  end tell"

sleep 2

section "Starting ngrok tunnel (tab 3)"
osascript -e "
  tell application \"Terminal\"
    activate
    tell application \"System Events\" to keystroke \"t\" using command down
    delay 0.5
    do script \"ngrok http --domain=$NGROK_DOMAIN 8080\" in front window
  end tell"

# ─── Summary ──────────────────────────────────────────────────────────────────

echo
echo "════════════════════════════════════════════════════════════"
echo "  Demo stack started"
echo "════════════════════════════════════════════════════════════"
echo "  Keycloak   : http://localhost:8888  (admin / admin)"
echo "  MCP server : http://localhost:8081"
echo "  Proxy      : http://localhost:8080"
echo "  Public URL : $NGROK_URL"
echo "────────────────────────────────────────────────────────────"
echo "  Test user  : testuser / Password123!"
echo "════════════════════════════════════════════════════════════"
echo
echo "Add to Claude Desktop connectors:"
echo "  URL: $NGROK_URL/mcp"
echo
echo "Ask Claude: \"What is the weather in Rome today?\""
echo
echo "Press Ctrl+C to stop and restore config.yaml"
echo
wait
