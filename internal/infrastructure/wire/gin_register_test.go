package wire

import (
	"bytes"
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestRegisterHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		requestBody        *auth.RegisterRequest
		mockResponse       *auth.RegisterResponse
		mockError          error
		expectedStatusCode int
		expectedResponse   *auth.RegisterResponse
	}{
		{
			name: "successful client registration",
			requestBody: &auth.RegisterRequest{
				ClientName:              "Test Client",
				RedirectURIs:            []string{"https://example.com/callback"},
				GrantTypes:              []string{"authorization_code"},
				ResponseTypes:           []string{"code"},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			mockResponse: &auth.RegisterResponse{
				ClientID:     "test_client_id",
				ClientSecret: "test_client_secret",
			},
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
			expectedResponse: &auth.RegisterResponse{
				ClientID:     "test_client_id",
				ClientSecret: "test_client_secret",
			},
		},
		{
			name: "auth service error",
			requestBody: &auth.RegisterRequest{
				ClientName:   "Test Client",
				RedirectURIs: []string{"https://example.com/callback"},
			},
			mockResponse:       nil,
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusInternalServerError,
			expectedResponse:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockProxy := new(MockProxy)
			mockEncryption := new(MockEncryption)

			if tt.mockError != nil {
				mockAuth.On("RegisterClient", tt.requestBody).Return((*auth.RegisterResponse)(nil), tt.mockError)
			} else {
				mockAuth.On("RegisterClient", tt.requestBody).Return(tt.mockResponse, nil)
			}

			// Mock the AuthMiddleware - always needed
			mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r)
				})
			})

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption)
			assert.NoError(t, err)

			// Create request body
			requestBodyJSON, _ := json.Marshal(tt.requestBody)

			// Create test request
			req, _ := http.NewRequest("POST", "/register", bytes.NewBuffer(requestBodyJSON))
			req.Header.Set("Content-Type", "application/json")
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)

			if tt.expectedResponse != nil {
				assert.Equal(t, "application/json; charset=utf-8", resp.Header().Get("Content-Type"))

				var responseBody auth.RegisterResponse
				err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, *tt.expectedResponse, responseBody)
			}

			// Verify mock expectations
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestRegisterHandlerInvalidJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mocks
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	// Mock the AuthMiddleware - always needed
	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	config := &config.Config{}

	// Create gin engine
	engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption)
	assert.NoError(t, err)

	// Create test request with invalid JSON
	req, _ := http.NewRequest("POST", "/register", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	resp := httptest.NewRecorder()

	// Execute request
	engine.ServeHTTP(resp, req)

	// Assertions
	assert.Equal(t, http.StatusBadRequest, resp.Code)
	assert.Contains(t, resp.Body.String(), "invalid_request")
}
