// cmd/mcpserver/main.go
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"log"
	"math/rand"
	"net/http"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

//go:embed weather_app.html
var weatherAppHTML string

func main() {

	runServer(":8081")

}

type GetWeatherParams struct {
	City string `json:"city" jsonschema:"City to get weather for (e.g. nyc, sf, boston, or all other cities)"`
	Date string `json:"date" jsonschema:"Date to get weather for (YYYY-MM-DD)"`
}

var weatherConditions = []string{
	"Sunny", "Partly Cloudy", "Cloudy", "Rainy", "Stormy", "Snowy", "Foggy", "Windy",
}

type WeatherResult struct {
	City         string  `json:"city"`
	Date         string  `json:"date"`
	Temperature  float64 `json:"temperature"`
	Condition    string  `json:"condition"`
	Humidity     int     `json:"humidity"`
	WindSpeed    float64 `json:"wind_speed"`
	HelloMessage string  `json:"hello_message,omitempty"`
}

func runServer(url string) {
	// Create an MCP server.
	server := mcp.NewServer(&mcp.Implementation{
		Name:    "weather-server",
		Version: "1.0.0",
	}, nil)

	const resourceURI = "ui://weather-server/app.html"

	// Add the cityWeather tool with MCP Apps UI declaration.
	mcp.AddTool(server, &mcp.Tool{
		Name:        "cityWeather",
		Description: "Get weather information for a specific city and date",
		Meta: mcp.Meta{
			"ui": map[string]any{
				"resourceUri": resourceURI,
			},
		},
	}, getWeather)

	// Serve the weather HTML app as a ui:// resource.
	server.AddResource(&mcp.Resource{
		URI:      resourceURI,
		Name:     "weather-app",
		MIMEType: "text/html;profile=mcp-app",
	}, func(_ context.Context, _ *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{
			Contents: []*mcp.ResourceContents{
				{URI: resourceURI, MIMEType: "text/html;profile=mcp-app", Text: weatherAppHTML},
			},
		}, nil
	})

	// Create the streamable HTTP handler (stateless: each POST is independent,
	// no session ID tracking — avoids 404 on stale session IDs from proxies).
	handler := mcp.NewStreamableHTTPHandler(func(req *http.Request) *mcp.Server {
		return server
	}, &mcp.StreamableHTTPOptions{Stateless: true})

	handlerWithLogging := loggingHandler(handler)

	log.Printf("MCP server listening on %s", url)
	log.Printf("Available tool: cityWeather, knowYourInfo")

	// Start the HTTP server with logging handler.
	if err := http.ListenAndServe(url, handlerWithLogging); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getWeather(ctx context.Context, req *mcp.CallToolRequest, params *GetWeatherParams) (*mcp.CallToolResult, any, error) {
	// Define time zones for each city
	response := generateFakeWeather(params.City, params.Date)

	// print req.Extra.Header
	log.Printf("Request Headers: %v", req.Extra.Header)

	user := ""

	// get all headers start with X- or X_ and add to user string
	for key, values := range req.Extra.Header {
		if len(values) > 0 && len(key) >= 2 && (key[:2] == "X-" || key[:2] == "X_") {
			if user != "" {
				user += ", "
			}
			user += key + ": " + values[0]
		}
	}

	if user == "" {
		user = "unknown user"
	}

	response.HelloMessage = "Hello, (" + user + ")! Here is the weather you requested."

	content, err := json.Marshal(response)
	if err != nil {
		log.Printf("Error marshalling response: %v", err)
		return nil, nil, err
	}

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
