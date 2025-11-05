#!/bin/bash
# Demo script for testing MCP Proxy with Test Server

set -e

echo "=========================================="
echo "MCP Proxy + Test Server Demo"
echo "=========================================="
echo ""

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

PROXY_URL="http://localhost:8080"
SERVER_URL="http://localhost:8081"

echo -e "${BLUE}Prerequisites:${NC}"
echo "1. MCP Test Server running on port 8081"
echo "2. MCP Proxy Server running on port 8080"
echo ""

# Check if servers are running
echo -e "${YELLOW}Checking servers...${NC}"

if curl -s "$SERVER_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Test Server is running on port 8081"
else
    echo -e "❌ Test Server NOT running. Start it with: task run-testserver"
    exit 1
fi

if curl -s "$PROXY_URL/health" > /dev/null 2>&1; then
    echo -e "${GREEN}✓${NC} Proxy Server is running on port 8080"
else
    echo -e "❌ Proxy Server NOT running. Start it with: task run"
    exit 1
fi

echo ""
echo "=========================================="
echo "1. Test Server Direct Access (No Auth)"
echo "=========================================="
echo ""

echo -e "${BLUE}Listing tools directly on test server...${NC}"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}' | jq '.result.tools[0].name'

echo ""
echo -e "${BLUE}Getting weather directly from test server...${NC}"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method":"tools/call",
    "params":{
      "name":"get_weather",
      "arguments":{
        "city":"London",
        "date":"2025-11-05"
      }
    }
  }' | jq -r '.result.content[0].text' | jq .

echo ""
echo "=========================================="
echo "2. Proxy Metadata Discovery"
echo "=========================================="
echo ""

echo -e "${BLUE}Checking proxy OpenID configuration...${NC}"
curl -s "$PROXY_URL/.well-known/openid-configuration" | jq .

echo ""
echo -e "${BLUE}Checking protected resource metadata...${NC}"
curl -s "$PROXY_URL/.well-known/oauth-protected-resource" | jq .

echo ""
echo "=========================================="
echo "3. Dynamic Client Registration"
echo "=========================================="
echo ""

echo -e "${BLUE}Registering a new client...${NC}"
REGISTER_RESPONSE=$(curl -s -X POST "$PROXY_URL/register" \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "Demo Test Client",
    "grant_types": ["authorization_code", "refresh_token"]
  }')

echo "$REGISTER_RESPONSE" | jq .

CLIENT_ID=$(echo "$REGISTER_RESPONSE" | jq -r '.client_id // empty')

if [ -z "$CLIENT_ID" ]; then
    echo ""
    echo -e "${YELLOW}Note: Dynamic client registration may not be fully implemented yet.${NC}"
    echo -e "${YELLOW}You can continue testing with a pre-configured client.${NC}"
else
    echo ""
    echo -e "${GREEN}✓${NC} Client registered: $CLIENT_ID"
fi

echo ""
echo "=========================================="
echo "4. Authorization Flow (Manual Steps)"
echo "=========================================="
echo ""

echo -e "${BLUE}To complete the OAuth flow:${NC}"
echo ""
echo "1. Initiate authorization (in browser):"
if [ -n "$CLIENT_ID" ]; then
    echo "   $PROXY_URL/auth?client_id=$CLIENT_ID&resource=$SERVER_URL&state=demo123"
else
    echo "   $PROXY_URL/auth?client_id={YOUR_CLIENT_ID}&resource=$SERVER_URL&state=demo123"
fi
echo ""
echo "2. After authentication, exchange code for token:"
echo "   curl -X POST $PROXY_URL/token \\"
echo "     -H 'Content-Type: application/x-www-form-urlencoded' \\"
echo "     -d 'grant_type=authorization_code' \\"
echo "     -d 'code={CODE_FROM_CALLBACK}' \\"
echo "     -d 'client_id={CLIENT_ID}'"
echo ""
echo "3. Use the token to call MCP through proxy:"
echo "   curl -X POST $PROXY_URL/mcp/tools/list \\"
echo "     -H 'Authorization: Bearer {ACCESS_TOKEN}' \\"
echo "     -H 'Content-Type: application/json' \\"
echo "     -d '{\"method\":\"tools/call\",\"params\":{...}}'"

echo ""
echo "=========================================="
echo "Demo Complete!"
echo "=========================================="
echo ""
echo -e "${GREEN}Summary:${NC}"
echo "• Test MCP Server: Running on $SERVER_URL"
echo "• MCP Proxy: Running on $PROXY_URL"
echo "• Available tool: get_weather (city, date)"
echo ""
echo "For complete testing guide, see: docs/testing-guide.md"
