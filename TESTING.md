# Testing Setup - Quick Start

## 🚀 One-Command Setup

Start both the MCP Test Server and Proxy:

```bash
task start-all
```

This will:
1. Build both binaries
2. Start MCP Test Server on port 8081
3. Start MCP Proxy on port 8080
4. Show live logs from both servers

Press `Ctrl+C` to stop both servers.

## 🧪 Testing

### Run the Demo

```bash
# In another terminal (while servers are running)
task demo
```

This will:
- Verify both servers are running
- Test direct access to the MCP server
- Check proxy metadata endpoints
- Attempt dynamic client registration
- Show instructions for OAuth flow

### Run Test Server Tests Only

```bash
task test-testserver
```

### Stop Servers

```bash
task stop-all
```

## 📁 Project Structure

```
mcp-janus/
├── cmd/
│   ├── mcpserver/          # Fake MCP test server
│   │   ├── main.go         # Weather tool implementation
│   │   ├── README.md       # Test server docs
│   │   └── QUICKREF.md     # Quick reference
│   └── proxy/              # MCP Proxy
│       └── main.go         # Proxy with Gin
├── scripts/
│   ├── start-servers.sh    # Start both servers
│   ├── stop-servers.sh     # Stop both servers
│   ├── demo-proxy.sh       # Full demo script
│   └── test-mcpserver.sh   # Test server unit tests
├── logs/                   # Server logs
│   ├── mcpserver.log
│   └── mcpproxy.log
├── config.yaml             # Configuration (now points to localhost)
└── Taskfile.yaml          # Task definitions
```

## 🔧 Configuration

The `config.yaml` has been updated to connect the proxy to the local test server:

```yaml
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"

upstreams:
  - name: weather-test
    resource: http://localhost:8081
    base_url: http://localhost:8081
    path_prefix: /mcp
```

## 🧰 Available Tasks

```bash
task --list
```

Key tasks:
- `task start-all` - Start both servers
- `task stop-all` - Stop both servers  
- `task demo` - Run demo script
- `task build-testserver` - Build test server only
- `task run-testserver` - Run test server only
- `task test-testserver` - Test the test server

## 🌐 Endpoints

### MCP Test Server (port 8081)
- `GET /health` - Health check
- `POST /mcp` - MCP protocol endpoint
  - Methods: `initialize`, `tools/list`, `tools/call`

### MCP Proxy (port 8080)
- `GET /health` - Health check
- `GET /.well-known/openid-configuration` - OpenID metadata
- `GET /.well-known/oauth-protected-resource` - Protected resource metadata
- `POST /register` - Dynamic client registration
- `GET /auth` - Start OAuth flow
- `POST /token` - Token endpoint
- `POST /mcp/*` - Proxied MCP calls (requires auth)

## 🔍 Manual Testing

### 1. Direct Test Server Access (No Auth)

```bash
# List tools
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}' | jq .

# Get weather
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method":"tools/call",
    "params":{
      "name":"get_weather",
      "arguments":{"city":"London","date":"2025-11-05"}
    }
  }' | jq .
```

### 2. Through Proxy (Requires OAuth)

See `docs/testing-guide.md` for the complete OAuth flow.

## 🐳 Docker Support

```bash
# Start with Docker Compose
docker-compose up

# Stop
docker-compose down
```

## 📝 Logs

View logs in real-time:

```bash
# Both servers
tail -f logs/mcpserver.log logs/mcpproxy.log

# Test server only
tail -f logs/mcpserver.log

# Proxy only
tail -f logs/mcpproxy.log
```

## 🎯 What to Test

1. **Test Server Functionality**
   - Health endpoint
   - Tool listing
   - Weather tool with various cities/dates
   - Error handling (invalid dates, missing params)

2. **Proxy Metadata**
   - OpenID configuration discovery
   - Protected resource metadata

3. **OAuth Flow**
   - Dynamic client registration
   - Authorization code flow with PKCE
   - Token issuance (opaque tokens)
   - Token validation

4. **Proxied MCP Calls**
   - Authenticated requests through proxy
   - Audience validation
   - Token expiry handling

## 📚 Documentation

- [Full Testing Guide](docs/testing-guide.md)
- [Test Server README](cmd/mcpserver/README.md)
- [Test Server Quick Ref](cmd/mcpserver/QUICKREF.md)
- [Main README](README.md)

## 🐛 Troubleshooting

**Servers won't start:**
```bash
# Check if ports are in use
lsof -ti:8080 -ti:8081

# Kill processes
task stop-all
```

**Build errors:**
```bash
# Clean and rebuild
task clean
go mod tidy
task build
task build-testserver
```

**Connection refused:**
- Make sure both servers are running: `task start-all`
- Check logs: `tail -f logs/*.log`
- Verify ports: `curl http://localhost:8081/health`
