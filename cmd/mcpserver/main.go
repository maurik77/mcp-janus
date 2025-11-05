// cmd/mcpserver/main.go
package main

import (
	"context"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func main() {

	runServer("localhost:8081")

}

type GetWeatherParams struct {
	City string `json:"city" jsonschema:"City to get weather for (nyc, sf, or boston)"`
	Date string `json:"date" jsonschema:"Date to get weather for (YYYY-MM-DD)"`
}

var weatherConditions = []string{
	"Sunny", "Partly Cloudy", "Cloudy", "Rainy", "Stormy", "Snowy", "Foggy", "Windy",
}

type WeatherResult struct {
	City        string  `json:"city"`
	Date        string  `json:"date"`
	Temperature float64 `json:"temperature"`
	Condition   string  `json:"condition"`
	Humidity    int     `json:"humidity"`
	WindSpeed   float64 `json:"wind_speed"`
}

func runServer(url string) {
	// Create an MCP server.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "time-server",
		Version: "1.0.0",
	}, nil)

	// Add the cityTime tool.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cityWeather",
		Description: "Get weather information for a specific city and date",
	}, getWeather)

	// Create the streamable HTTP handler.
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, nil)

	handlerWithLogging := loggingHandler(handler)

	log.Printf("MCP server listening on %s", url)
	log.Printf("Available tool: cityWeather")

	// Start the HTTP server with logging handler.
	if err := http.ListenAndServe(url, handlerWithLogging); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getWeather(ctx context.Context, req *mcp.CallToolRequest, params *GetWeatherParams) (*mcp.CallToolResult, any, error) {
	// Define time zones for each city
	response := generateFakeWeather(params.City, params.Date)

	content, _ := json.Marshal(response)

	return &mcp.CallToolResult{
		Content: []mcp.Content{
			&mcp.TextContent{
				Text: string(content),
			},
		},
	}, nil, nil
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
