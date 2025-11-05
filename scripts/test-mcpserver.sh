#!/bin/bash
# Test script for MCP Server

SERVER_URL="http://localhost:8081"

echo "=== Testing MCP Server ==="
echo ""

echo "1. Health Check"
echo "----------------"
curl -s "$SERVER_URL/health" | jq .
echo ""
echo ""

echo "2. Initialize MCP Connection"
echo "-----------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "initialize",
    "params": {}
  }' | jq .
echo ""
echo ""

echo "3. List Available Tools"
echo "------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/list",
    "params": {}
  }' | jq .
echo ""
echo ""

echo "4. Get Weather for London on 2025-11-05"
echo "-----------------------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
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
  }' | jq .
echo ""
echo ""

echo "5. Get Weather for Tokyo on 2025-12-25"
echo "----------------------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {
        "city": "Tokyo",
        "date": "2025-12-25"
      }
    }
  }' | jq .
echo ""
echo ""

echo "6. Test Error - Invalid Date Format"
echo "-------------------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "get_weather",
      "arguments": {
        "city": "Paris",
        "date": "2025/11/05"
      }
    }
  }' | jq .
echo ""
echo ""

echo "7. Test Error - Unknown Tool"
echo "------------------------------"
curl -s -X POST "$SERVER_URL/mcp" \
  -H "Content-Type: application/json" \
  -d '{
    "method": "tools/call",
    "params": {
      "name": "unknown_tool",
      "arguments": {}
    }
  }' | jq .
echo ""

echo "=== All Tests Complete ==="
