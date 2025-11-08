package wire

import (
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestOpenIDConfigurationEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		mockResponse       map[string]any
		expectedStatusCode int
	}{
		{
			name: "successful openid configuration",
			mockResponse: map[string]any{
				"issuer":                 "https://example.com",
				"authorization_endpoint": "https://example.com/auth",
				"token_endpoint":         "https://example.com/token",
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "empty configuration",
			mockResponse:       map[string]any{},
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockEncryption := new(MockEncryption)

			mockMetadata.On("OpenIDConfiguration").Return(tt.mockResponse)

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockEncryption)
			assert.NoError(t, err)

			// Create test request
			req, _ := http.NewRequest("GET", "/.well-known/openid-configuration", nil)
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)
			assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

			var responseBody map[string]any
			err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse, responseBody)

			// Verify mock expectations
			mockMetadata.AssertExpectations(t)
		})
	}
}

func TestProtectedResourceMetadataEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		mockResponse       map[string]any
		expectedStatusCode int
	}{
		{
			name: "successful protected resource metadata",
			mockResponse: map[string]any{
				"resource":              "https://example.com/api",
				"authorization_servers": []string{"https://example.com"},
			},
			expectedStatusCode: http.StatusOK,
		},
		{
			name:               "empty metadata",
			mockResponse:       map[string]any{},
			expectedStatusCode: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockEncryption := new(MockEncryption)

			mockMetadata.On("ProtectedResourceMetadata").Return(tt.mockResponse)

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockEncryption)
			assert.NoError(t, err)

			// Create test request
			req, _ := http.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)
			assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

			var responseBody map[string]any
			err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
			assert.NoError(t, err)
			assert.Equal(t, tt.mockResponse, responseBody)

			// Verify mock expectations
			mockMetadata.AssertExpectations(t)
		})
	}
}

func TestHealthEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mocks
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockEncryption := new(MockEncryption)

	config := &config.Config{}

	// Create gin engine
	engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockEncryption)
	assert.NoError(t, err)

	// Create test request
	req, _ := http.NewRequest("GET", "/health", nil)
	resp := httptest.NewRecorder()

	// Execute request
	engine.ServeHTTP(resp, req)

	// Assertions
	assert.Equal(t, http.StatusOK, resp.Code)
	assert.Equal(t, "OK", resp.Body.String())
}
