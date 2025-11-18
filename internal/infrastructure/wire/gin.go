package wire

import (
	"context"
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/infrastructure/telemetry"
	"mcpproxy/internal/server"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
)

type contextKey int

const (
	metricsKey contextKey = iota
)

func NewGinEngine(config *config.Config,
	authService auth.Service,
	metadataService metadata.Service,
	proxy server.Proxy,
	encryption utility.Encryption,
	metrics *telemetry.Metrics) (*gin.Engine, error) {
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	// Router
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// OpenTelemetry middleware
	r.Use(otelgin.Middleware("mcp-proxy"))

	// Custom timeout middleware
	r.Use(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})

	// Metrics middleware - inject metrics into context
	r.Use(func(c *gin.Context) {
		ctx := context.WithValue(c.Request.Context(), metricsKey, metrics)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	})

	// Discovery
	r.GET("/.well-known/openid-configuration", ginMetadataHandler(metadataService.OpenIDConfiguration))
	r.GET("/.well-known/oauth-protected-resource", ginMetadataHandler(metadataService.ProtectedResourceMetadata))

	// Dynamic Client Registration
	r.POST("/register", registerHandler(authService))

	// Authorization Code Flow
	r.GET("/auth", authHandler(authService))
	r.GET("/callback", callbackHandler(authService))
	r.POST("/token", tokenHandler(authService))
	r.POST("/refresh", refreshHandler(authService))

	// Proxy API - with auth middleware
	authorized := r.Group("/mcp")
	authorized.Use(ginAuthMiddleware(proxy))
	{
		authorized.Any("/*path", func(c *gin.Context) {
			proxy.ProxyHandler(c.Writer, c.Request)
		})
	}

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	return r, nil
}

// authHandler: client → Proxy

func authHandler(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := c.Request.Context().Value(metricsKey).(*telemetry.Metrics)
		req := &auth.AuthenticateRequest{}
		err := c.Bind(req)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		metrics.RecordAuthRequest(c.Request.Context(), req.ClientID)

		authURL, err := authService.AuthenticateRequest(req)

		if err != nil {
			metrics.RecordAuthFailure(c.Request.Context(), req.ClientID, "authentication_failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		metrics.RecordAuthSuccess(c.Request.Context(), req.ClientID)
		c.Redirect(http.StatusFound, authURL)
	}
}

// callbackHandler: IdP → Proxy
func callbackHandler(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &auth.AuthorizationCodeData{}
		err := c.BindQuery(req)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		authData, redirectURL, err := authService.ManageAuthorizationCode(req)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		query := redirectURL.Query()
		query.Set("code", authData.Code)
		query.Set("state", authData.State)
		redirectURL.RawQuery = query.Encode()

		c.Redirect(http.StatusFound, redirectURL.String())
	}
}

// tokenHandler: client → Proxy
func tokenHandler(authHandler auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := c.Request.Context().Value(metricsKey).(*telemetry.Metrics)
		req := &auth.AccessTokenRequest{}
		err := c.Bind(req)

		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		start := time.Now()
		opaqueToken, err := authHandler.RetrieveAccessToken(req)
		duration := time.Since(start)

		if err != nil {
			metrics.RecordTokenExchange(c.Request.Context(), duration, false)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		metrics.RecordTokenExchange(c.Request.Context(), duration, true)
		c.JSON(http.StatusOK, opaqueToken)
	}
}

// refreshHandler
func refreshHandler(_ auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusNotImplemented, gin.H{"error": "not_implemented"})
	}
}

func registerHandler(authHandler auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := c.Request.Context().Value(metricsKey).(*telemetry.Metrics)
		req := &auth.RegisterRequest{}
		if err := json.NewDecoder(c.Request.Body).Decode(req); err != nil {
			metrics.RecordClientRegistration(c.Request.Context(), false)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		res, err := authHandler.RegisterClient(req)

		if err != nil {
			metrics.RecordClientRegistration(c.Request.Context(), false)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		metrics.RecordClientRegistration(c.Request.Context(), true)
		c.JSON(http.StatusOK, res)
	}
}

// ginHandler wraps http.HandlerFunc for Gin
func ginMetadataHandler(metadata func() any) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata()
		c.JSON(http.StatusOK, data)
	}
}

// ginAuthMiddleware wraps the auth middleware for Gin
func ginAuthMiddleware(proxy server.Proxy) gin.HandlerFunc {
	middleware := proxy.AuthMiddleware()
	return func(c *gin.Context) {
		var handlerCalled bool
		wrappedHandler := middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			c.Request = r
		}))
		wrappedHandler.ServeHTTP(c.Writer, c.Request)
		if handlerCalled {
			c.Next()
		} else {
			c.Abort()
		}
	}
}
