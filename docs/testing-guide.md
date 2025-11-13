# Testing the MCP Proxy with the Test Server

This guide shows how to test the complete MCP proxy flow using the test weather server.

## Setup

### 1. Start the MCP Test Server

```bash
# Build and run
go build -o bin/mcpserver ./cmd/mcpserver
./bin/mcpserver
```

The server runs on `http://localhost:8081`

### 2. Configure the Proxy

Add the test server as an upstream in your `config.yaml`:

```yaml
upstreams:
  - name: weather-test
    url: http://localhost:8081/mcp
    timeout: 30s
    allowed_methods:
      - tools/list
      - tools/call
      - initialize
```

### 3. Start the MCP Proxy

```bash
go build -o bin/mcpproxy ./cmd/proxy
./bin/mcpproxy
```

## Testing Flow

### Step 1: Register a Client (Dynamic Client Registration)

```bash
curl -X POST http://localhost:8080/register \
  -H "Content-Type: application/json" \
  -d '{
    "redirect_uris": ["http://localhost:3000/callback"],
    "client_name": "Test Client",
    "grant_types": ["authorization_code", "refresh_token"]
  }'
```

Save the `client_id` from the response.

### Step 2: Start Authorization Flow

```bash
# Replace {CLIENT_ID} with your client_id
curl "http://localhost:8080/auth?client_id={CLIENT_ID}&resource=http://localhost:8081&state=test123"
```

This will redirect you to the IdP for authentication.

### Step 3: Exchange Code for Token

After authentication, exchange the authorization code for an access token:

```bash
curl -X POST http://localhost:8080/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code={AUTHORIZATION_CODE}" \
  -d "client_id={CLIENT_ID}"
```

Save the `access_token`.

### Step 4: Call MCP Tool Through Proxy

Now use the token to call the weather tool through the proxy:

```bash
# List tools
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/list"
  }'

# Get weather
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer {ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {
        "city": "New York",
        "date": "2025-11-10"
      }
    }
  }'
```

## Direct Testing (Without Proxy)

You can also test the MCP server directly without the proxy:

```bash
# Use the test script
./scripts/test-mcpserver.sh

# Or manually test endpoints
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {
        "city": "Paris",
        "date": "2025-11-05"
      }
    }
  }'
```

## Expected Results

### Successful Weather Query

```json
{
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"city\":\"Paris\",\"date\":\"2025-11-05\",\"temperature\":25.4,\"condition\":\"Sunny\",\"humidity\":62,\"wind_speed\":15.3}"
      }
    ]
  }
}
```

### Error: Invalid Date Format

```json
{
  "error": {
    "code": -32602,
    "message": "Invalid date format. Use YYYY-MM-DD"
  }
}
```

### Error: Missing Parameter

```json
{
  "error": {
    "code": -32602,
    "message": "Missing required parameter: city"
  }
}
```

## Architecture

```
┌─────────────┐
│ MCP Client  │
└──────┬──────┘
       │ 1. Auth Flow
       │ 2. Get Token
       ▼
┌──────────────────┐
│   MCP Proxy      │ ← OAuth 2.0 + Token Management
│  (Port 8080)     │
└──────┬───────────┘
       │ 3. Authenticated Request
       │ 4. Forward with Upstream Token
       ▼
┌──────────────────┐
│  MCP Test Server │ ← Fake Weather Tool
│  (Port 8081)     │
└──────────────────┘
```

## Notes

- The weather data is deterministic - same city/date always returns same weather
- All weather data is completely fake
- The test server implements the basic MCP protocol structure
- Perfect for testing authentication, authorization, and proxy forwarding logic
