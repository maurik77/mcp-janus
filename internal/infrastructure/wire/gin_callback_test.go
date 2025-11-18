package wire

import (
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestCallbackHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		queryParams        map[string]string
		mockAuthData       *auth.AuthorizationCodeData
		mockRedirectURL    *url.URL
		mockError          error
		expectedStatusCode int
		expectedLocation   string
	}{
		{
			name: "successful callback",
			queryParams: map[string]string{
				"code":  "auth_code_123",
				"state": "callback_state",
			},
			mockAuthData: &auth.AuthorizationCodeData{
				Code:  "proxy_code_456",
				State: "proxy_state",
			},
			mockRedirectURL: &url.URL{
				Scheme: "https",
				Host:   "client.example.com",
				Path:   "/callback",
			},
			mockError:          nil,
			expectedStatusCode: http.StatusFound,
			expectedLocation:   "https://client.example.com/callback?code=proxy_code_456&state=proxy_state",
		},
		{
			name: "auth service error",
			queryParams: map[string]string{
				"code":  "auth_code_123",
				"state": "callback_state",
			},
			mockAuthData:       nil,
			mockRedirectURL:    nil,
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusBadRequest,
			expectedLocation:   "",
		},
		{
			name: "missing code parameter",
			queryParams: map[string]string{
				"state": "callback_state",
			},
			mockAuthData:       nil,
			mockRedirectURL:    nil,
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusBadRequest,
			expectedLocation:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockProxy := new(MockProxy)
			mockEncryption := new(MockEncryption)

			expectedRequest := &auth.AuthorizationCodeData{
				Code:  tt.queryParams["code"],
				State: tt.queryParams["state"],
			}

			// Always set up the mock expectation since the handler always calls ManageAuthorizationCode
			mockAuth.On("ManageAuthorizationCode", expectedRequest).Return(tt.mockAuthData, tt.mockRedirectURL, tt.mockError)

			// Mock the AuthMiddleware - always needed
			mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r)
				})
			})

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
			assert.NoError(t, err)

			// Build URL with query parameters
			requestURL := "/callback"
			if len(tt.queryParams) > 0 {
				params := url.Values{}
				for key, value := range tt.queryParams {
					params.Add(key, value)
				}
				requestURL += "?" + params.Encode()
			}

			// Create test request
			req, _ := http.NewRequest("GET", requestURL, nil)
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)

			if tt.expectedLocation != "" {
				assert.Equal(t, tt.expectedLocation, resp.Header().Get("Location"))
			}

			// Verify mock expectations
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestCallbackHandlerWithError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mocks
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	// Mock the service to handle any authorization code request
	mockAuth.On("ManageAuthorizationCode", &auth.AuthorizationCodeData{
		Code:  "",
		State: "",
	}).Return((*auth.AuthorizationCodeData)(nil), (*url.URL)(nil), assert.AnError)

	// Mock the AuthMiddleware - always needed
	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	config := &config.Config{}

	// Create gin engine
	engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
	assert.NoError(t, err)

	// Test callback with error parameter (OAuth error response)
	req, _ := http.NewRequest("GET", "/callback?error=access_denied&error_description=User+denied+access", nil)
	resp := httptest.NewRecorder()

	// Execute request
	engine.ServeHTTP(resp, req)

	// Should handle OAuth error responses
	// The actual behavior depends on the implementation
	assert.NotEqual(t, http.StatusOK, resp.Code)
}
