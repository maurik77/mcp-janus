package server

import (
	"context"
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
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

// makeProxyJWT creates a valid JWT (alg=none) for use in proxy-mode tests.
func makeProxyJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	require.NoError(t, err)
	return signed
}

func makeSelfIssuedBlob(t *testing.T, expiresAt int64, claims map[string]string) []byte {
	t.Helper()
	si := auth.SelfIssuedTokenData{
		Type:      "si",
		IssuedAt:  time.Now().Add(-time.Hour).Unix(),
		ExpiresAt: expiresAt,
		Claims:    claims,
	}
	b, err := json.Marshal(si)
	require.NoError(t, err)
	return b
}

// --- NewProxy Tests ---

func TestNewProxy(t *testing.T) {
	t.Run("valid upstream URL", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "http://localhost:8081",
			},
		}
		p, err := NewProxy(cfg, nil, nil)
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
		p, err := NewProxy(cfg, nil, nil)
		require.NoError(t, err)
		assert.NotNil(t, p)
	})

	t.Run("empty upstream URL", func(t *testing.T) {
		cfg := config.Config{
			Upstream: config.Upstream{
				BaseURL: "",
			},
		}
		p, err := NewProxy(cfg, nil, nil)
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
		p, err := NewProxy(cfg, nil, nil)
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
		p, err := NewProxy(cfg, nil, nil)
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
	p, err := NewProxy(cfg, metaSvc, nil)
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
	p, err := NewProxy(cfg, metaSvc, enc)
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

func TestAuthMiddleware_ProxyMode_InvalidJWT(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	enc := new(mockEncryption)
	enc.On("Decrypt", "opaque-token").Return([]byte("not-a-jwt"), nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, enc)
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

func TestAuthMiddleware_ProxyMode_ExpiredJWT(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	enc := new(mockEncryption)
	expiredJWT := makeProxyJWT(t, jwt.MapClaims{
		"sub": "user-123",
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Hour)),
	})
	enc.On("Decrypt", "opaque-token").Return([]byte(expiredJWT), nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler should not be called for expired JWT")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_Success(t *testing.T) {
	metaSvc := new(mockMetadataService)

	enc := new(mockEncryption)
	validJWT := makeProxyJWT(t, jwt.MapClaims{
		"sub":   "user-123",
		"email": "user@example.com",
		"count": float64(42), // non-string claim — should be skipped
		"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	enc.On("Decrypt", "opaque-token").Return([]byte(validJWT), nil)

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
	p, err := NewProxy(cfg, metaSvc, enc)
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

	// Opaque token forwarded upstream
	realToken := capturedRequest.Context().Value(keyRealToken)
	assert.Equal(t, "opaque-token", realToken)
}

func TestAuthMiddleware_SelfIssuedToken_Valid(t *testing.T) {
	metaSvc := new(mockMetadataService)
	enc := new(mockEncryption)

	siBlob := makeSelfIssuedBlob(t, time.Now().Add(23*time.Hour).Unix(),
		map[string]string{"X-Sub": "user-123", "X-Email": "user@example.com"})
	enc.On("Decrypt", "opaque-si-token").Return(siBlob, nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
		IDP: config.IDP{
			FixedHeaders: map[string]string{"X-Tenant": "test-tenant"},
		},
	}
	p, err := NewProxy(cfg, metaSvc, enc)
	require.NoError(t, err)

	var capturedReq *http.Request
	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer opaque-si-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	require.NotNil(t, capturedReq)
	assert.Equal(t, "user-123", capturedReq.Header.Get("X-Sub"))
	assert.Equal(t, "user@example.com", capturedReq.Header.Get("X-Email"))
	assert.Equal(t, "test-tenant", capturedReq.Header.Get("X-Tenant"))
	assert.Equal(t, "opaque-si-token", capturedReq.Context().Value(keyRealToken))
}

func TestAuthMiddleware_SelfIssuedToken_Expired(t *testing.T) {
	metaSvc := new(mockMetadataService)
	enc := new(mockEncryption)

	siBlob := makeSelfIssuedBlob(t, time.Now().Add(-time.Hour).Unix(), // expired
		map[string]string{"X-Sub": "user-123"})
	enc.On("Decrypt", "expired-si-token").Return(siBlob, nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for expired token")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer expired-si-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_SelfIssuedToken_WrongDiscriminator_FallsBackToJWT(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")
	enc := new(mockEncryption)

	// JSON with wrong type discriminator — falls through to JWT parse path, which fails
	wrongBlob, _ := json.Marshal(map[string]any{"t": "other", "exp": 9999999999, "iat": 1000, "cl": map[string]string{}})
	enc.On("Decrypt", "wrong-type-token").Return(wrongBlob, nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, enc)
	require.NoError(t, err)

	middleware := p.AuthMiddleware()
	handler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called when JWT parse fails")
	}))

	req := httptest.NewRequest("GET", "/mcp/test", nil)
	req.Header.Set("Authorization", "Bearer wrong-type-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestAuthMiddleware_InvalidBearerFormat(t *testing.T) {
	metaSvc := new(mockMetadataService)
	metaSvc.On("WWWAuthenticateHeader").Return("Bearer")

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, metaSvc, nil)
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

// --- ProxyHandler Tests ---

func TestProxyHandler_ForwardsRequest(t *testing.T) {
	var upstreamReceived *http.Request
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceived = r
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL, Name: "test-upstream"},
	}
	p, err := NewProxy(cfg, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/ping", nil)
	rec := httptest.NewRecorder()

	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, upstreamReceived)
	assert.Equal(t, "/mcp/ping", upstreamReceived.URL.Path)
}

func TestProxyHandler_ForwardsRealToken(t *testing.T) {
	var authHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}
	p, err := NewProxy(cfg, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/tool", nil)
	ctx := context.WithValue(req.Context(), keyRealToken, "real-idp-jwt")
	req = req.WithContext(ctx)

	rec := httptest.NewRecorder()
	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Bearer real-idp-jwt", authHeader)
}

func TestProxyHandler_ModifyResponse_StripsServerHeader(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream-server/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}
	p, err := NewProxy(cfg, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/tool", nil)
	rec := httptest.NewRecorder()
	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Server"), "Server header should be stripped by ModifyResponse")
}

// --- Backward-compatibility tests: develop-issued TokenBehaviorProxy tokens ---
//
// develop issues opaque tokens as: AES-256-GCM_encrypt(raw_idp_jwt_bytes)
// where raw_idp_jwt is a fully signed JWT (e.g. HS256/RS256) from the IdP.
//
// The current branch's resolveToken calls ParseUnverified instead of re-validating
// the signature via JWKS on every request. These tests confirm that a token issued
// by develop is accepted (or rejected for expiry) by the current branch.

func makeSignedJWT(t *testing.T, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	raw, err := tok.SignedString([]byte("idp-secret"))
	require.NoError(t, err)
	return raw
}

func TestResolveToken_ProxyMode_DevelopTokenCompat(t *testing.T) {
	tests := []struct {
		name        string
		claims      jwt.MapClaims
		claimsMap   map[string]string
		wantSub     string
		wantHeaders map[string]string
		wantErr     bool
	}{
		{
			name: "valid develop token maps claims",
			claims: jwt.MapClaims{
				"sub":   "alice",
				"email": "alice@example.com",
				"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			claimsMap:   map[string]string{"sub": "X-Sub", "email": "X-Email"},
			wantSub:     "alice",
			wantHeaders: map[string]string{"X-Sub": "alice", "X-Email": "alice@example.com"},
		},
		{
			name: "valid develop token without sub",
			claims: jwt.MapClaims{
				"email": "anon@example.com",
				"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
			},
			claimsMap:   map[string]string{"email": "X-Email"},
			wantSub:     "",
			wantHeaders: map[string]string{"X-Email": "anon@example.com"},
		},
		{
			name: "expired develop token is rejected",
			claims: jwt.MapClaims{
				"sub": "alice",
				"exp": jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			},
			wantErr: true,
		},
		{
			name: "develop token without exp is rejected",
			claims: jwt.MapClaims{
				"sub": "alice",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rawJWT := makeSignedJWT(t, tt.claims)

			cfg := config.Config{
				Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
				IDP:      config.IDP{ClaimsMapping: tt.claimsMap},
			}
			p, err := NewProxy(cfg, nil, nil)
			require.NoError(t, err)
			pp := p.(*proxy)

			headers, upstreamTok, sub, err := pp.resolveToken([]byte(rawJWT), "opaque-blob")
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			// Upstream always receives the original opaque token, not the raw JWT.
			assert.Equal(t, "opaque-blob", upstreamTok)
			assert.Equal(t, tt.wantSub, sub)
			for k, v := range tt.wantHeaders {
				assert.Equal(t, v, headers[k], "header %s", k)
			}
		})
	}
}

func TestAuthMiddleware_ProxyMode_DevelopTokenCompat_Valid(t *testing.T) {
	// Simulates a token issued by the develop branch and consumed by the current branch.
	// develop: opaque = encrypt(signed_idp_jwt); current branch: ParseUnverified + expiry.
	rawJWT := makeSignedJWT(t, jwt.MapClaims{
		"sub":   "user-develop",
		"email": "dev@example.com",
		"exp":   jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})

	enc := new(mockEncryption)
	enc.On("Decrypt", "develop-opaque-token").Return([]byte(rawJWT), nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
		IDP: config.IDP{
			ClaimsMapping: map[string]string{
				"sub":   "X-User-Sub",
				"email": "X-User-Email",
			},
		},
	}
	p, err := NewProxy(cfg, nil, enc)
	require.NoError(t, err)

	var capturedReq *http.Request
	handler := p.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedReq = r
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/mcp/tool", nil)
	req.Header.Set("Authorization", "Bearer develop-opaque-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "develop-issued token must be accepted")
	require.NotNil(t, capturedReq)
	assert.Equal(t, "user-develop", capturedReq.Header.Get("X-User-Sub"))
	assert.Equal(t, "dev@example.com", capturedReq.Header.Get("X-User-Email"))
	assert.Equal(t, "develop-opaque-token", capturedReq.Context().Value(keyRealToken))
}

func TestAuthMiddleware_ProxyMode_DevelopTokenCompat_Expired(t *testing.T) {
	// An expired develop-issued token must be rejected even without JWKS re-validation.
	rawJWT := makeSignedJWT(t, jwt.MapClaims{
		"sub": "user-develop",
		"exp": jwt.NewNumericDate(time.Now().Add(-time.Minute)),
	})

	enc := new(mockEncryption)
	enc.On("Decrypt", "expired-develop-token").Return([]byte(rawJWT), nil)

	cfg := config.Config{
		Upstream: config.Upstream{BaseURL: "http://localhost:8081"},
	}
	p, err := NewProxy(cfg, nil, enc)
	require.NoError(t, err)

	handler := p.AuthMiddleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("next handler must not be called for expired develop token")
	}))

	req := httptest.NewRequest("GET", "/mcp/tool", nil)
	req.Header.Set("Authorization", "Bearer expired-develop-token")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_token")
}

func TestNewProxy_WithPathPrefix(t *testing.T) {
	var receivedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Upstream: config.Upstream{
			BaseURL:    upstream.URL,
			PathPrefix: "/v2",
		},
	}
	p, err := NewProxy(cfg, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/tool", nil)
	rec := httptest.NewRecorder()
	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	// SetURL prepends the prefix path to the original request path
	assert.Equal(t, "/v2/mcp/tool", receivedPath)
}
