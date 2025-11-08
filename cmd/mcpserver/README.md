# MCP Test Server

A simple MCP (Model Context Protocol) server for testing the MCP proxy implementation.

## Features

This server implements a fake weather tool that returns weather information for any city and date.

### Available Tools

- **get_weather**: Get weather information for a specific city and date
  - Parameters:
    - `city` (string, required): The name of the city
    - `date` (string, required): The date in YYYY-MM-DD format
  - Returns: Fake weather data including temperature, condition, humidity, and wind speed

## Running the Server

```bash
# Build
go build -o bin/mcpserver ./cmd/mcpserver

# Run
./bin/mcpserver
```

The server starts on port `8081` by default.

## Testing

### 1. Health Check

```bash
curl http://localhost:8081/health
```

### 2. Initialize MCP Connection

```bash
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "initialize",
    "params": {}
  }'
```

### 3. List Available Tools

```bash
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/list",
    "params": {}
  }'
```

### 4. Call the Weather Tool

```bash
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {
        "city": "London",
        "date": "2025-11-05"
      }
    }
  }'
```

Expected response:
```json
{
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"city\":\"London\",\"date\":\"2025-11-05\",\"temperature\":22.3,\"condition\":\"Partly Cloudy\",\"humidity\":65,\"wind_speed\":12.5}"
      }
    ]
  }
}
```

## Using with MCP Proxy

To test the MCP proxy with this server:

1. Configure the proxy to point to this server as an upstream
2. Use the proxy's OAuth flow to get a token
3. Make authenticated requests through the proxy to this server

## Notes

- The weather data is **completely fake** and generated deterministically based on the city and date
- The same city/date combination will always return the same weather data
- This is for testing purposes only
