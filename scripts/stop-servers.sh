#!/bin/bash
# Stop MCP servers

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "Stopping MCP servers..."

# Kill by port
lsof -ti:8081 | xargs kill -9 2>/dev/null && echo "✓ Stopped server on port 8081" || echo "No process on port 8081"
lsof -ti:8080 | xargs kill -9 2>/dev/null && echo "✓ Stopped server on port 8080" || echo "No process on port 8080"

# Kill by PID if files exist
if [ -f "$PROJECT_DIR/logs/mcpserver.pid" ]; then
    kill $(cat "$PROJECT_DIR/logs/mcpserver.pid") 2>/dev/null && echo "✓ Killed mcpserver" || true
    rm "$PROJECT_DIR/logs/mcpserver.pid"
fi

if [ -f "$PROJECT_DIR/logs/mcpproxy.pid" ]; then
    kill $(cat "$PROJECT_DIR/logs/mcpproxy.pid") 2>/dev/null && echo "✓ Killed mcpproxy" || true
    rm "$PROJECT_DIR/logs/mcpproxy.pid"
fi

echo "Done."
