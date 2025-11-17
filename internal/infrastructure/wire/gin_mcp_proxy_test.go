package wire

import (
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestMCPProxyEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		path               string
		method             string
		authHeader         string
		expectedStatusCode int
	}{
		{
			name:               "unauthorized request - missing auth header",
			path:               "/mcp/test",
			method:             "GET",
			authHeader:         "",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "unauthorized request - invalid auth header",
			path:               "/mcp/test",
			method:             "GET",
			authHeader:         "Invalid token",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "POST to MCP endpoint without auth",
			path:               "/mcp/api/call",
			method:             "POST",
			authHeader:         "",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "PUT to MCP endpoint without auth",
			path:               "/mcp/resource/123",
			method:             "PUT",
			authHeader:         "",
			expectedStatusCode: http.StatusUnauthorized,
		},
		{
			name:               "DELETE to MCP endpoint without auth",
			path:               "/mcp/resource/123",
			method:             "DELETE",
			authHeader:         "",
			expectedStatusCode: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockProxy := new(MockProxy)
			mockEncryption := new(MockEncryption)

			// Mock the AuthMiddleware to return a middleware that rejects unauthorized requests
			mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					authHeader := r.Header.Get("Authorization")
					if authHeader == "" || authHeader == "Invalid token" {
						w.Header().Set("WWW-Authenticate", "Bearer realm=\"mcp-proxy\"")
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					next.ServeHTTP(w, r)
				})
			})

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
			assert.NoError(t, err)

			// Create test request
			req, _ := http.NewRequest(tt.method, tt.path, nil)
			if tt.authHeader != "" {
				req.Header.Set("Authorization", tt.authHeader)
			}
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)

			if tt.expectedStatusCode == http.StatusUnauthorized {
				// Should include WWW-Authenticate header for 401 responses
				assert.NotEmpty(t, resp.Header().Get("WWW-Authenticate"))
			}

			// Verify mock expectations
			mockProxy.AssertExpectations(t)
		})
	}
}

func TestMCPProxyEndpointWithValidAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// This test would require mocking the encryption and token validation
	// For now, we'll test the structure

	// Setup mocks
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	// Mock the AuthMiddleware to reject unauthorized requests
	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	})

	config := &config.Config{}

	// Create gin engine
	engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
	assert.NoError(t, err)

	// Test that the endpoint exists and responds
	req, _ := http.NewRequest("GET", "/mcp/test", nil)
	resp := httptest.NewRecorder()

	// Execute request
	engine.ServeHTTP(resp, req)

	// Should return 401 without valid auth (auth middleware should catch this)
	assert.Equal(t, http.StatusUnauthorized, resp.Code)
}

func TestMCPProxyEndpointCatchAll(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Test that the catch-all pattern works for various paths
	paths := []string{
		"/mcp/",
		"/mcp/api",
		"/mcp/api/v1",
		"/mcp/api/v1/resource",
		"/mcp/deep/nested/path/test",
	}

	for _, path := range paths {
		t.Run("path: "+path, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockProxy := new(MockProxy)
			mockEncryption := new(MockEncryption)

			// Mock the AuthMiddleware to reject unauthorized requests
			mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusUnauthorized)
				})
			})

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
			assert.NoError(t, err)

			// Create test request
			req, _ := http.NewRequest("GET", path, nil)
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Should be caught by the MCP proxy handler (even if auth fails)
			// The status will be 401 due to missing auth, but it proves the route exists
			assert.Equal(t, http.StatusUnauthorized, resp.Code)
		})
	}
}
