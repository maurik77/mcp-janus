#!/bin/bash
# Start both MCP Test Server and Proxy for testing

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "=========================================="
echo "Starting MCP Test Environment"
echo "=========================================="
echo ""

# Build if needed
echo -e "${BLUE}Building binaries...${NC}"
task build 2>/dev/null || go build -o bin/mcpproxy ./cmd/proxy
task build-testserver 2>/dev/null || go build -o bin/mcpserver ./cmd/mcpserver
echo -e "${GREEN}✓${NC} Binaries built"
echo ""

# Kill any existing processes
echo -e "${YELLOW}Cleaning up existing processes...${NC}"
lsof -ti:8081 | xargs kill -9 2>/dev/null || true
lsof -ti:8080 | xargs kill -9 2>/dev/null || true
sleep 1

# Start test server
echo -e "${BLUE}Starting MCP Test Server (port 8081)...${NC}"
./bin/mcpserver > logs/mcpserver.log 2>&1 &
MCPSERVER_PID=$!
echo -e "${GREEN}✓${NC} Test Server started (PID: $MCPSERVER_PID)"

# Wait for test server to be ready
sleep 2
if ! curl -s http://localhost:8081/health > /dev/null 2>&1; then
    echo -e "❌ Test Server failed to start"
    cat logs/mcpserver.log
    exit 1
fi

# Start proxy
echo -e "${BLUE}Starting MCP Proxy (port 8080)...${NC}"
./bin/mcpproxy > logs/mcpproxy.log 2>&1 &
MCPPROXY_PID=$!
echo -e "${GREEN}✓${NC} Proxy started (PID: $MCPPROXY_PID)"

# Wait for proxy to be ready
sleep 2
if ! curl -s http://localhost:8080/health > /dev/null 2>&1; then
    echo -e "❌ Proxy failed to start"
    cat logs/mcpproxy.log
    kill $MCPSERVER_PID 2>/dev/null || true
    exit 1
fi

echo ""
echo "=========================================="
echo -e "${GREEN}✓ Both servers are running!${NC}"
echo "=========================================="
echo ""
echo "MCP Test Server: http://localhost:8081"
echo "MCP Proxy:       http://localhost:8080"
echo ""
echo "PIDs: mcpserver=$MCPSERVER_PID, mcpproxy=$MCPPROXY_PID"
echo ""
echo "Logs:"
echo "  tail -f logs/mcpserver.log"
echo "  tail -f logs/mcpproxy.log"
echo ""
echo "To stop:"
echo "  kill $MCPSERVER_PID $MCPPROXY_PID"
echo "  or: ./scripts/stop-servers.sh"
echo ""
echo "Run tests:"
echo "  ./scripts/demo-proxy.sh"
echo ""

# Save PIDs
mkdir -p logs
echo "$MCPSERVER_PID" > logs/mcpserver.pid
echo "$MCPPROXY_PID" > logs/mcpproxy.pid

echo "Press Ctrl+C to stop and view logs..."
echo ""

# Trap Ctrl+C
trap "echo ''; echo 'Stopping servers...'; kill $MCPSERVER_PID $MCPPROXY_PID 2>/dev/null; exit 0" INT

# Keep script running and show logs
tail -f logs/mcpserver.log logs/mcpproxy.log
