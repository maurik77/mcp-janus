package server

import (
	"context"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// --- Mocks ---

type mockMetadataService struct {
	mock.Mock
}

func (m *mockMetadataService) OpenIDConfiguration() any {
	args := m.Called()
	return args.Get(0)
}

func (m *mockMetadataService) AuthorizationServerMetadata() any {
	args := m.Called()
	return args.Get(0)
}

func (m *mockMetadataService) ProtectedResourceMetadata() any {
	args := m.Called()
	return args.Get(0)
}

func (m *mockMetadataService) WWWAuthenticateHeader() string {
	args := m.Called()
	return args.String(0)
}

type mockAuthService struct {
	mock.Mock
}

func (m *mockAuthService) RegisterClient(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
}

func (m *mockAuthService) ValidateJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
	args := m.Called(ctx, tokenString)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *mockAuthService) AuthenticateRequest(ctx context.Context, req *auth.AuthenticateRequest) (string, error) {
	args := m.Called(ctx, req)
	return args.String(0), args.Error(1)
}

func (m *mockAuthService) ManageAuthorizationCode(ctx context.Context, req *auth.AuthorizationCodeData) (*auth.AuthorizationCodeData, *url.URL, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*auth.AuthorizationCodeData), args.Get(1).(*url.URL), args.Error(2)
}

func (m *mockAuthService) RetrieveAccessToken(ctx context.Context, req *auth.AccessTokenRequest) (*oauth2.Token, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *mockAuthService) RefreshToken(ctx context.Context, req *auth.RefreshTokenRequest) (*oauth2.Token, error) {
	args := m.Called(ctx, req)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

type mockEncryption struct {
	mock.Mock
}

func (m *mockEncryption) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *mockEncryption) Decrypt(encrypted string) ([]byte, error) {
	args := m.Called(encrypted)
	return args.Get(0).([]byte), args.Error(1)
}

// --- NewProxy Tests ---

func TestNewProxy(t *testing.T) {
	t.Run("valid upstream URL", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "http://localhost:8081",
			},
		}
		p, err := NewProxy(cfg, nil, nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, p)
	})

	t.Run("valid upstream URL with path prefix", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL:    "http://localhost:8081",
				PathPrefix: "/api/v1",
			},
		}
		p, err := NewProxy(cfg, nil, nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, p)
	})

	t.Run("empty upstream URL", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "",
			},
		}
		p, err := NewProxy(cfg, nil, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, p)
		assert.Contains(t, err.Error(), "must be an absolute URL")
	})

	t.Run("relative upstream URL", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "/just/a/path",
			},
		}
		p, err := NewProxy(cfg, nil, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, p)
		assert.Contains(t, err.Error(), "must be an absolute URL")
	})

	t.Run("missing scheme", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "localhost:8081",
			},
		}
		p, err := NewProxy(cfg, nil, nil, nil)
		assert.Error(t, err)
		assert.Nil(t, p)
	})
}

// --- extractBearerToken Tests ---

func TestExtractBearerToken(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		wantToken string
		wantOk    bool
	}{
		{"valid bearer", "Bearer abc123", "abc123", true},
		{"empty header", "", "", false},
		{"no bearer prefix", "Basic abc123", "", false},
		{"bearer lowercase", "bearer abc123", "", false},
		{"just Bearer keyword", "Bearer ", "", true},
		{"bearer with spaces in token", "Bearer token with spaces", "token with spaces", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			if tt.authValue != "" {
				r.Header.Set("Authorization", tt.authValue)
			}
			token, ok := extractBearerToken(r)
			assert.Equal(t, tt.wantOk, ok)
			assert.Equal(t, tt.wantToken, token)
		})
	}
}

// --- AuthMiddleware Tests ---

func TestAuthMiddleware_MissingToken(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return(`Bearer resource_metadata="http://localhost/.well-known/oauth-protected-resource"`)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, nil, nil)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
	assert.NotEmpty(t, rec.Header().Get("WWW-Authenticate"))
}

func TestAuthMiddleware_DecryptionFailure(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	enc := new(mockEncryption)
	enc.On("Decrypt", "bad-opaque-token").Return([]byte(nil), assert.AnError)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, nil, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer bad-opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_JWTValidationFailure(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	enc := new(mockEncryption)
	enc.On("Decrypt", "opaque-token").Return([]byte("invalid-jwt-string"), nil)

	authSvc := new(mockAuthService)
	authSvc.On("ValidateJWT", mock.Anything, "invalid-jwt-string").Return((*jwt.Token)(nil), assert.AnError)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_ClaimsNotMapClaims(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	enc := new(mockEncryption)
	enc.On("Decrypt", "opaque-token").Return([]byte("real-jwt"), nil)

	// Return a valid token but with non-MapClaims
	token := &jwt.Token{
		Valid:  true,
		Claims: &jwt.RegisteredClaims{Subject: "user1"},
	}
	authSvc := new(mockAuthService)
	authSvc.On("ValidateJWT", mock.Anything, "real-jwt").Return(token, nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called when claims are not MapClaims")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestAuthMiddleware_Success(t *testing.T) {
	metaSvc := new(mockMetadataService)

	enc := new(mockEncryption)
	enc.On("Decrypt", "opaque-token").Return([]byte("real-jwt"), nil)

	token := &jwt.Token{
		Valid: true,
		Claims: jwt.MapClaims{
			"sub":   "user-123",
			"email": "user@example.com",
			"count": float64(42), // non-string claim — should be skipped
		},
	}
	authSvc := new(mockAuthService)
	authSvc.On("ValidateJWT", mock.Anything, "real-jwt").Return(token, nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
		IDP: config.IDP{
			ClaimsMapping: map[string]string{
				"sub":   "X-Sub",
				"email": "X-Email",
				"count": "X-Count",
			},
		},
	}
	p, err := NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)

	var capturedRequest *http.Request
	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRequest = r
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedRequest)

	// String claims should be mapped to headers
	assert.Equal(t, "user-123", capturedRequest.Header.Get("X-Sub"))
	assert.Equal(t, "user@example.com", capturedRequest.Header.Get("X-Email"))

	// Non-string claim should be skipped (not panic)
	assert.Empty(t, capturedRequest.Header.Get("X-Count"))

	// Real token should be in context
	realToken := capturedRequest.Context().Value(keyRealToken)
	assert.Equal(t, "opaque-token", realToken)
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, nil, nil)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}
