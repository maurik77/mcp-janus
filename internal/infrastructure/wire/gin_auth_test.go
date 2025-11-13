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

func TestAuthHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		queryParams        map[string]string
		mockAuthURL        string
		mockError          error
		expectedStatusCode int
		expectedLocation   string
	}{
		{
			name: "successful authorization request",
			queryParams: map[string]string{
				"client_id":             "test_client",
				"state":                 "test_state",
				"code_challenge":        "test_challenge",
				"redirect_uri":          "https://example.com/callback",
				"code_challenge_method": "S256",
			},
			mockAuthURL:        "https://auth.example.com/authorize?client_id=test_client&state=test_state",
			mockError:          nil,
			expectedStatusCode: http.StatusFound,
			expectedLocation:   "https://auth.example.com/authorize?client_id=test_client&state=test_state",
		},
		{
			name: "auth service error",
			queryParams: map[string]string{
				"client_id": "test_client",
				"state":     "test_state",
			},
			mockAuthURL:        "",
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusInternalServerError,
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

			expectedRequest := &auth.AuthenticateRequest{
				ClientID:            tt.queryParams["client_id"],
				State:               tt.queryParams["state"],
				CodeChallenge:       tt.queryParams["code_challenge"],
				RedirectURI:         tt.queryParams["redirect_uri"],
				CodeChallengeMethod: tt.queryParams["code_challenge_method"],
			}

			mockAuth.On("AuthenticateRequest", expectedRequest).Return(tt.mockAuthURL, tt.mockError)

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

			// Build URL with query parameters
			requestURL := "/auth"
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

func TestAuthHandlerInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Setup mocks
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	// Mock the service to handle empty authentication request
	mockAuth.On("AuthenticateRequest", &auth.AuthenticateRequest{
		ClientID:            "",
		State:               "",
		CodeChallenge:       "",
		RedirectURI:         "",
		CodeChallengeMethod: "",
	}).Return("", assert.AnError)

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

	// Create test request with invalid parameters (missing required fields)
	req, _ := http.NewRequest("GET", "/auth", nil)
	resp := httptest.NewRecorder()

	// Execute request
	engine.ServeHTTP(resp, req)

	// Assertions - should handle empty request gracefully
	// The actual behavior depends on the implementation of AuthenticateRequest
	assert.NotEqual(t, http.StatusOK, resp.Code) // Should not return 200 for empty request
}
