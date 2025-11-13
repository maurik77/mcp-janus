# MCP Janus Testing Architecture

## Complete Setup

```
┌──────────────────────────────────────────────────────────────┐
│                     Testing Environment                       │
└──────────────────────────────────────────────────────────────┘

┌─────────────────┐
│   HTTP Client   │  (curl, Postman, etc.)
└────────┬────────┘
         │
         │ 1. Direct Access (No Auth) ✓
         ├────────────────────────────────────┐
         │                                    │
         │ 2. Via Proxy (OAuth Required)     │
         ▼                                    ▼
┌──────────────────────┐            ┌─────────────────────┐
│    MCP Proxy         │            │  MCP Test Server    │
│   (Port 8080)        │            │   (Port 8081)       │
│                      │            │                     │
│  ┌────────────────┐  │            │  ┌───────────────┐  │
│  │ OAuth Provider │  │            │  │ Fake Weather  │  │
│  │ - Registration │  │            │  │     Tool      │  │
│  │ - Authorization│  │            │  │               │  │
│  │ - Token Issue  │  │   3. Auth  │  │ Returns:      │  │
│  └────────────────┘  │─────────▶  │  │ - Temp        │  │
│                      │            │  │ - Condition   │  │
│  ┌────────────────┐  │            │  │ - Humidity    │  │
│  │ Opaque Tokens  │  │            │  │ - Wind        │  │
│  │ - AEAD Crypto  │  │            │  └───────────────┘  │
│  │ - Validation   │  │            │                     │
│  └────────────────┘  │            │  Built with Gin     │
│                      │            │  Stateless          │
│  ┌────────────────┐  │            │  Deterministic      │
│  │ MCP Forwarding │  │            └─────────────────────┘
│  │ - Audience     │  │
│  │ - Resource     │  │
│  └────────────────┘  │
│                      │
│  Built with Gin      │
│  OAuth 2.1           │
└──────────────────────┘
```

## Request Flow

### Direct Access (Testing)

```
curl → POST /mcp → Test Server → Weather Data
                   (port 8081)
```

### Via Proxy (Production-like)

```
1. Register Client
   curl → POST /register → Proxy → client_id + redirect_uri

2. Authorization
   Browser → GET /auth → Proxy → OAuth Flow → Authorization Code

3. Token Exchange
   curl → POST /token → Proxy → Opaque Bearer Token (encrypted)

4. MCP Call
   curl → POST /mcp/tools/call
        + Authorization: Bearer {opaque_token}
        ↓
        Proxy:
        - Decrypt token
        - Validate audience
        - Extract upstream creds
        ↓
        Test Server:
        - Execute get_weather
        - Return fake data
        ↓
        Proxy → Response → Client
```

## Component Details

### MCP Test Server (cmd/mcpserver)
- **Language**: Go with Gin
- **Port**: 8081
- **Authentication**: None (open for testing)
- **Tools**: 
  - `get_weather(city, date)` → Fake weather data
- **Methods**:
  - `initialize` - Server info
  - `tools/list` - Available tools
  - `tools/call` - Execute tool

### MCP Proxy (cmd/proxy)
- **Language**: Go with Gin
- **Port**: 8080
- **Authentication**: OAuth 2.1 + PKCE
- **Token Type**: Opaque (AEAD encrypted)
- **Features**:
  - Dynamic Client Registration (RFC 7591)
  - Authorization Server Discovery (RFC 8414)
  - Protected Resource Metadata (RFC 9728)
  - Audience Binding (RFC 8707)
  - Key Rotation Support

## Configuration Mapping

```yaml
config.yaml
├── proxy
│   ├── base_url: http://localhost:8080  ◄── Proxy address
│   └── listen_addr: ":8080"             ◄── Proxy port
├── idp
│   └── (OAuth provider config)
├── encryption
│   └── master_key                       ◄── AEAD key
└── upstreams
    └── - name: weather-test
        ├── resource: http://localhost:8081   ◄── Test server
        ├── base_url: http://localhost:8081
        └── path_prefix: /mcp
```

## Testing Scenarios

### ✅ Scenario 1: Test Server Only
**Purpose**: Verify MCP protocol implementation

```bash
task run-testserver
curl POST http://localhost:8081/mcp
```

### ✅ Scenario 2: Full OAuth Flow
**Purpose**: Test authentication & authorization

```bash
task start-all
# 1. Register client
# 2. Get authorization code
# 3. Exchange for token
# 4. Call MCP with token
```

### ✅ Scenario 3: Token Validation
**Purpose**: Test security controls

```bash
# Test expired tokens
# Test wrong audience
# Test invalid tokens
```

### ✅ Scenario 4: Proxied MCP Calls
**Purpose**: End-to-end integration

```bash
Client → Proxy (validate token) → Server (execute) → Proxy → Client
```

## Quick Commands

```bash
# Start everything
task start-all

# Run demo
task demo

# Direct test
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}'

# Stop everything
task stop-all
```

## Ports & URLs

| Service      | Port | Base URL                  | Health Check                    |
|--------------|------|---------------------------|---------------------------------|
| Test Server  | 8081 | http://localhost:8081     | GET /health                     |
| Proxy        | 8080 | http://localhost:8080     | GET /health                     |

## Security Notes

🔒 **Test Server**: NO AUTHENTICATION (intentional for testing)
🔐 **Proxy**: FULL OAUTH 2.1 + Opaque Tokens + AEAD Encryption

The test server is intentionally open to allow easy testing of the proxy's security layer.
