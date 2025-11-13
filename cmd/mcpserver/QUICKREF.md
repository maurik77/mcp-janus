# MCP Test Server - Quick Reference

## Building

```bash
# Using task
task build-testserver

# Or directly with go
go build -o bin/mcpserver ./cmd/mcpserver
```

## Running

```bash
# Using task
task run-testserver

# Or directly
./bin/mcpserver
```

Server starts on **http://localhost:8081**

## Available Endpoints

### Health Check
```bash
GET /health
```

### MCP Protocol Endpoint
```bash
POST /mcp
Content-Type: application/json
```

## MCP Methods

### 1. Initialize
```json
{
  "method": "initialize",
  "params": {}
}
```

### 2. List Tools
```json
{
  "method": "tools/list",
  "params": {}
}
```

### 3. Call Tool - Get Weather
```json
{
  "method": "tools/call",
  "params": {
    "name": "get_weather",
    "arguments": {
      "city": "London",
      "date": "2025-11-05"
    }
  }
}
```

## Quick Test Examples

```bash
# List tools
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/list"}'

# Get weather for New York
curl -X POST http://localhost:8081/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "method":"tools/call",
    "params":{
      "name":"get_weather",
      "arguments":{
        "city":"New York",
        "date":"2025-12-25"
      }
    }
  }'

# Run all tests
./scripts/test-mcpserver.sh
```

## Expected Response Format

### Success
```json
{
  "result": {
    "content": [
      {
        "type": "text",
        "text": "{\"city\":\"London\",\"date\":\"2025-11-05\",\"temperature\":33.3,\"condition\":\"Windy\",\"humidity\":79,\"wind_speed\":24.9}"
      }
    ]
  }
}
```

### Error
```json
{
  "error": {
    "code": -32602,
    "message": "Invalid date format. Use YYYY-MM-DD"
  }
}
```

## Features

- ✅ Implements MCP protocol structure
- ✅ Fake weather data generation (deterministic)
- ✅ Full error handling
- ✅ Built with Gin for performance
- ✅ Structured logging
- ✅ Perfect for testing proxy authentication/authorization

## Notes

- Weather data is **completely fake**
- Same city + date = same weather (deterministic)
- No external dependencies required
- Runs standalone without configuration
