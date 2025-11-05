// cmd/mcpserver/main.go
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

// MCP Protocol structures
type MCPRequest struct {
	Method string                 `json:"method"`
	Params map[string]interface{} `json:"params,omitempty"`
}

type MCPResponse struct {
	Result interface{} `json:"result,omitempty"`
	Error  *MCPError   `json:"error,omitempty"`
}

type MCPError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool structures
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

type InputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties"`
	Required   []string            `json:"required"`
}

type Property struct {
	Type        string `json:"type"`
	Description string `json:"description"`
}

// Weather response structure
type WeatherResult struct {
	City        string  `json:"city"`
	Date        string  `json:"date"`
	Temperature float64 `json:"temperature"`
	Condition   string  `json:"condition"`
	Humidity    int     `json:"humidity"`
	WindSpeed   float64 `json:"wind_speed"`
}

var weatherConditions = []string{
	"Sunny", "Partly Cloudy", "Cloudy", "Rainy", "Stormy", "Snowy", "Foggy", "Windy",
}

func main() {
	rand.Seed(time.Now().UnixNano())

	gin.SetMode(gin.ReleaseMode)
	r := gin.Default()

	// MCP endpoints
	r.POST("/mcp", handleMCPRequest)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	port := "8081"
	log.Printf("MCP Test Server starting on :%s", port)
	log.Printf("Available tools: get_weather")
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func handleMCPRequest(c *gin.Context) {
	var req MCPRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, MCPResponse{
			Error: &MCPError{
				Code:    -32700,
				Message: "Parse error",
			},
		})
		return
	}

	log.Printf("MCP Request: method=%s, params=%v", req.Method, req.Params)

	switch req.Method {
	case "tools/list":
		handleToolsList(c)
	case "tools/call":
		handleToolsCall(c, req.Params)
	case "initialize":
		handleInitialize(c)
	default:
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32601,
				Message: fmt.Sprintf("Method not found: %s", req.Method),
			},
		})
	}
}

func handleInitialize(c *gin.Context) {
	c.JSON(http.StatusOK, MCPResponse{
		Result: map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]interface{}{
				"name":    "test-weather-server",
				"version": "1.0.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		},
	})
}

func handleToolsList(c *gin.Context) {
	tools := []Tool{
		{
			Name:        "get_weather",
			Description: "Get weather information for a specific city and date",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"city": {
						Type:        "string",
						Description: "The name of the city",
					},
					"date": {
						Type:        "string",
						Description: "The date in YYYY-MM-DD format",
					},
				},
				Required: []string{"city", "date"},
			},
		},
	}

	c.JSON(http.StatusOK, MCPResponse{
		Result: map[string]interface{}{
			"tools": tools,
		},
	})
}

func handleToolsCall(c *gin.Context, params map[string]interface{}) {
	toolName, ok := params["name"].(string)
	if !ok {
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params: missing tool name",
			},
		})
		return
	}

	arguments, ok := params["arguments"].(map[string]interface{})
	if !ok {
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid params: missing arguments",
			},
		})
		return
	}

	switch toolName {
	case "get_weather":
		handleGetWeather(c, arguments)
	default:
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: fmt.Sprintf("Unknown tool: %s", toolName),
			},
		})
	}
}

func handleGetWeather(c *gin.Context, args map[string]interface{}) {
	city, ok := args["city"].(string)
	if !ok {
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required parameter: city",
			},
		})
		return
	}

	date, ok := args["date"].(string)
	if !ok {
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Missing required parameter: date",
			},
		})
		return
	}

	// Validate date format
	_, err := time.Parse("2006-01-02", date)
	if err != nil {
		c.JSON(http.StatusOK, MCPResponse{
			Error: &MCPError{
				Code:    -32602,
				Message: "Invalid date format. Use YYYY-MM-DD",
			},
		})
		return
	}

	// Generate fake weather data
	weather := generateFakeWeather(city, date)

	// Format as MCP tool result
	content, _ := json.Marshal(weather)

	c.JSON(http.StatusOK, MCPResponse{
		Result: map[string]interface{}{
			"content": []map[string]interface{}{
				{
					"type": "text",
					"text": string(content),
				},
			},
		},
	})
}

func generateFakeWeather(city, date string) WeatherResult {
	// Use city and date as seed for consistent results
	seed := int64(0)
	for _, c := range city + date {
		seed += int64(c)
	}
	r := rand.New(rand.NewSource(seed))

	// Generate fake but realistic weather data
	temp := 5.0 + r.Float64()*30.0 // Temperature between 5°C and 35°C
	condition := weatherConditions[r.Intn(len(weatherConditions))]
	humidity := 30 + r.Intn(70)     // Humidity between 30% and 100%
	windSpeed := r.Float64() * 50.0 // Wind speed between 0 and 50 km/h

	return WeatherResult{
		City:        city,
		Date:        date,
		Temperature: float64(int(temp*10)) / 10, // Round to 1 decimal
		Condition:   condition,
		Humidity:    humidity,
		WindSpeed:   float64(int(windSpeed*10)) / 10, // Round to 1 decimal
	}
}
