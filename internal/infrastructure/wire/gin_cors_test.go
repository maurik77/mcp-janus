package wire

import (
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func corsTestEngine(t *testing.T, corsEnabled bool, allowedOrigins []string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)

	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		})
	})

	cfg := &config.Config{}
	cfg.Proxy.CORS.Enabled = corsEnabled
	cfg.Proxy.CORS.AllowedOrigins = allowedOrigins
	cfg.Proxy.CORS.AllowedMethods = []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"}
	cfg.Proxy.CORS.AllowedHeaders = []string{"Authorization", "Content-Type", "Accept",
		"Mcp-Session-Id", "Mcp-Protocol-Version", "x-custom-auth-headers"}
	cfg.Proxy.CORS.ExposedHeaders = []string{"WWW-Authenticate", "Mcp-Session-Id"}

	engine, err := NewGinEngine(cfg, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
	assert.NoError(t, err)
	return engine
}

func TestCORS_PreflightMCPEndpoint(t *testing.T) {
	engine := corsTestEngine(t, true, []string{"http://localhost:6274"})

	req := httptest.NewRequest(http.MethodOptions, "/mcp/foo", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "authorization,x-custom-auth-headers")
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusNoContent, rec.Code)
	assert.Equal(t, "http://localhost:6274", rec.Header().Get("Access-Control-Allow-Origin"))
	assert.NotEmpty(t, rec.Header().Get("Access-Control-Allow-Methods"))
	assert.NotEmpty(t, rec.Header().Get("Access-Control-Allow-Headers"))
}

func TestCORS_ActualRequestAddsHeader(t *testing.T) {
	mockMetadata := new(MockMetadataService)
	mockAuth := new(MockAuthService)
	mockProxy := new(MockProxy)
	mockEncryption := new(MockEncryption)

	gin.SetMode(gin.TestMode)
	mockProxy.On("AuthMiddleware").Return(func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			next.ServeHTTP(w, r)
		})
	})
	mockMetadata.On("ProtectedResourceMetadata").Return(map[string]any{"resource": "http://localhost:8080/mcp"})

	cfg := &config.Config{}
	cfg.Proxy.CORS.Enabled = true
	cfg.Proxy.CORS.AllowedOrigins = []string{"http://localhost:6274"}
	cfg.Proxy.CORS.AllowedMethods = []string{"GET", "POST", "OPTIONS"}
	cfg.Proxy.CORS.AllowedHeaders = []string{"Authorization", "Content-Type"}

	engine, err := NewGinEngine(cfg, mockAuth, mockMetadata, mockProxy, mockEncryption, createTestMetrics())
	assert.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "http://localhost:6274", rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_DisabledPreflightHitsAuth(t *testing.T) {
	engine := corsTestEngine(t, false, nil)

	req := httptest.NewRequest(http.MethodOptions, "/mcp/foo", nil)
	req.Header.Set("Origin", "http://localhost:6274")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	// Without CORS middleware the OPTIONS request hits ginAuthMiddleware and gets 401
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_UnknownOriginRejected(t *testing.T) {
	engine := corsTestEngine(t, true, []string{"http://localhost:6274"})

	req := httptest.NewRequest(http.MethodOptions, "/mcp/foo", nil)
	req.Header.Set("Origin", "http://evil.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	engine.ServeHTTP(rec, req)

	assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
}
