package wire

import (
	"bytes"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

func TestRefreshHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	successToken := &oauth2.Token{
		AccessToken:  "new_opaque_access",
		RefreshToken: "new_opaque_refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(1 * time.Hour),
	}

	tests := []struct {
		name               string
		requestBody        string
		contentType        string
		mockToken          *oauth2.Token
		mockError          error
		expectedStatusCode int
		expectedBody       string
	}{
		{
			name:               "successful refresh - JSON",
			requestBody:        `{"refresh_token": "encrypted_refresh_token"}`,
			contentType:        "application/json",
			mockToken:          successToken,
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
			expectedBody:       "new_opaque_access",
		},
		{
			name:               "successful refresh - form data",
			requestBody:        "refresh_token=encrypted_refresh_token",
			contentType:        "application/x-www-form-urlencoded",
			mockToken:          successToken,
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
			expectedBody:       "new_opaque_access",
		},
		{
			name:               "explicit grant_type=refresh_token",
			requestBody:        `{"grant_type": "refresh_token", "refresh_token": "encrypted_refresh_token"}`,
			contentType:        "application/json",
			mockToken:          successToken,
			mockError:          nil,
			expectedStatusCode: http.StatusOK,
			expectedBody:       "new_opaque_access",
		},
		{
			name:               "wrong grant_type",
			requestBody:        `{"grant_type": "authorization_code", "refresh_token": "encrypted_refresh_token"}`,
			contentType:        "application/json",
			mockToken:          nil,
			mockError:          nil,
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "unsupported_grant_type",
		},
		{
			name:               "refresh service error",
			requestBody:        `{"refresh_token": "bad_token"}`,
			contentType:        "application/json",
			mockToken:          (*oauth2.Token)(nil),
			mockError:          assert.AnError,
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "invalid_grant",
		},
		{
			name:               "empty refresh token",
			requestBody:        `{"refresh_token": ""}`,
			contentType:        "application/json",
			mockToken:          nil,
			mockError:          nil,
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "invalid_request",
		},
		{
			name:               "missing refresh token",
			requestBody:        `{}`,
			contentType:        "application/json",
			mockToken:          nil,
			mockError:          nil,
			expectedStatusCode: http.StatusBadRequest,
			expectedBody:       "invalid_request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockMetadata := new(MockMetadataService)
			mockAuth := new(MockAuthService)
			mockProxy := new(MockProxy)
			mockEncryption := new(MockEncryption)

			mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					next.ServeHTTP(w, r)
				})
			})

			if tt.mockToken != nil || tt.mockError != nil {
				mockAuth.On("RefreshToken", mock.MatchedBy(func(req *auth.RefreshTokenRequest) bool {
					return req != nil && req.RefreshToken != ""
				})).Return(tt.mockToken, tt.mockError)
			}

			cfg := &config.Config{}
			engine, err := NewGinEngine(cfg, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
			assert.NoError(t, err)

			req, _ := http.NewRequest("POST", "/refresh", bytes.NewBufferString(tt.requestBody))
			req.Header.Set("Content-Type", tt.contentType)
			resp := httptest.NewRecorder()

			engine.ServeHTTP(resp, req)

			assert.Equal(t, tt.expectedStatusCode, resp.Code)
			assert.Contains(t, resp.Body.String(), tt.expectedBody)
		})
	}
}

func TestRefreshHandlerDifferentMethods(t *testing.T) {
	gin.SetMode(gin.TestMode)

	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})

	cfg := &config.Config{}
	engine, err := NewGinEngine(cfg, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
	assert.NoError(t, err)

	tests := []struct {
		name   string
		method string
	}{
		{name: "GET method should not be allowed", method: "GET"},
		{name: "PUT method should not be allowed", method: "PUT"},
		{name: "DELETE method should not be allowed", method: "DELETE"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest(tt.method, "/refresh", nil)
			resp := httptest.NewRecorder()
			engine.ServeHTTP(resp, req)
			assert.True(t, resp.Code == http.StatusNotFound || resp.Code == http.StatusMethodNotAllowed)
		})
	}
}
