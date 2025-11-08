package wire

import (
	"bytes"
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"golang.org/x/oauth2"
)

func TestTokenHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		requestBody        *auth.AccessTokenRequest
		contentType        string
		mockToken          *oauth2.Token
		mockError          error
		expectedStatusCode int
	}{
		{
			name: "successful token exchange - JSON",
			requestBody: &auth.AccessTokenRequest{
				Code:         "auth_code_123",
				RedirectURI:  "https://example.com/callback",
				ClientSecret: "client_secret",
				CodeVerifier: "code_verifier",
				ClientID:     "test_client",
			},
			contentType: "application/json",
			mockToken: &oauth2.Token{
				AccessToken:  "opaque_access_token",
				TokenType:    "Bearer",
				RefreshToken: "refresh_token",
			},
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "successful token exchange - form data",
			requestBody: &auth.AccessTokenRequest{
				Code:         "auth_code_123",
				RedirectURI:  "https://example.com/callback",
				ClientSecret: "client_secret",
				CodeVerifier: "code_verifier",
				ClientID:     "test_client",
			},
			contentType: "application/x-www-form-urlencoded",
			mockToken: &oauth2.Token{
				AccessToken:  "opaque_access_token",
				TokenType:    "Bearer",
				RefreshToken: "refresh_token",
			},
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
		},
		{
			name: "auth service error",
			requestBody: &auth.AccessTokenRequest{
				Code:        "invalid_code",
				RedirectURI: "https://example.com/callback",
				ClientID:    "test_client",
			},
			contentType:        "application/json",
			mockToken:          nil,
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockEncryption := new(MockEncryption)

			if tt.mockError != nil {
				mockAuth.On("RetrieveAccessToken", tt.requestBody).Return((*oauth2.Token)(nil), tt.mockError)
			} else {
				mockAuth.On("RetrieveAccessToken", tt.requestBody).Return(tt.mockToken, nil)
			}

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockEncryption)
			assert.NoError(t, err)

			var req *http.Request

			// Create request based on content type
			if tt.contentType == "application/json" {
				requestBodyJSON, _ := json.Marshal(tt.requestBody)
				req, _ = http.NewRequest("POST", "/token", bytes.NewBuffer(requestBodyJSON))
				req.Header.Set("Content-Type", "application/json")
			} else {
				// Form data
				form := url.Values{}
				form.Add("code", tt.requestBody.Code)
				form.Add("redirect_uri", tt.requestBody.RedirectURI)
				form.Add("client_secret", tt.requestBody.ClientSecret)
				form.Add("code_verifier", tt.requestBody.CodeVerifier)
				form.Add("client_id", tt.requestBody.ClientID)

				req, _ = http.NewRequest("POST", "/token", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, tt.expectedStatusCode, resp.Code)

			if tt.mockToken != nil {
				assert.Equal(t, "application/json", resp.Header().Get("Content-Type"))

				var responseBody oauth2.Token
				err = json.Unmarshal(resp.Body.Bytes(), &responseBody)
				assert.NoError(t, err)
				assert.Equal(t, tt.mockToken.AccessToken, responseBody.AccessToken)
				assert.Equal(t, tt.mockToken.TokenType, responseBody.TokenType)
				assert.Equal(t, tt.mockToken.RefreshToken, responseBody.RefreshToken)
			}

			// Verify mock expectations
			mockAuth.AssertExpectations(t)
		})
	}
}

func TestTokenHandlerInvalidRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name        string
		requestBody string
		contentType string
	}{
		{
			name:        "invalid JSON",
			requestBody: "invalid json",
			contentType: "application/json",
		},
		{
			name:        "empty request body",
			requestBody: "",
			contentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Setup mocks
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockEncryption := new(MockEncryption)

			config := &config.Config{}

			// Create gin engine
			engine, err := NewGinEngine(config, mockAuth, mockMetadata, mockEncryption)
			assert.NoError(t, err)

			// Create test request
			req, _ := http.NewRequest("POST", "/token", strings.NewReader(tt.requestBody))
			req.Header.Set("Content-Type", tt.contentType)
			resp := httptest.NewRecorder()

			// Execute request
			engine.ServeHTTP(resp, req)

			// Assertions
			assert.Equal(t, http.StatusBadRequest, resp.Code)
			assert.Contains(t, resp.Body.String(), "invalid_request")
		})
	}
}
