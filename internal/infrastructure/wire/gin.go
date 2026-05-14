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
		handler := func(c *gin.Context) { proxy.ProxyHandler(c.Writer, c.Request) }
		authorized.Any("", handler)
		authorized.Any("/*path", handler)
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
			utility.Logger.Warn().Err(err).Msg("auth: failed to bind request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		utility.Logger.Info().Str("client_id", req.ClientID).Str("redirect_uri", req.RedirectURI).Msg("auth: request received")
		metrics.RecordAuthRequest(c.Request.Context(), req.ClientID)

		authURL, err := authService.AuthenticateRequest(c.Request.Context(), req)

		if err != nil {
			utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("auth: authentication failed")
			metrics.RecordAuthFailure(c.Request.Context(), req.ClientID, "authentication_failed")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		utility.Logger.Info().Str("client_id", req.ClientID).Msg("auth: redirecting to IdP")
		metrics.RecordAuthSuccess(c.Request.Context(), req.ClientID)
		c.Redirect(http.StatusFound, authURL)
	}
}

// callbackHandler: IdP → Proxy
func callbackHandler(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		// RFC 6749 §4.1.2.1: propagate IdP errors back to the client redirect URI
		if idpErr := c.Query("error"); idpErr != "" {
			utility.Logger.Warn().Str("idp_error", idpErr).Str("description", c.Query("error_description")).Msg("callback: IdP returned error")
			c.JSON(http.StatusBadRequest, gin.H{
				"error":             idpErr,
				"error_description": c.Query("error_description"),
			})
			return
		}

		req := &auth.AuthorizationCodeData{}
		err := c.BindQuery(req)

		if err != nil {
			utility.Logger.Warn().Err(err).Msg("callback: failed to bind query params")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		utility.Logger.Info().Msg("callback: authorization code received from IdP")
		authData, redirectURL, err := authService.ManageAuthorizationCode(c.Request.Context(), req)

		if err != nil {
			utility.Logger.Error().Err(err).Msg("callback: failed to manage authorization code")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		query := redirectURL.Query()
		query.Set("code", authData.Code)
		query.Set("state", authData.State)
		redirectURL.RawQuery = query.Encode()

		utility.Logger.Info().Str("redirect_host", redirectURL.Host).Msg("callback: redirecting to client")
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
			utility.Logger.Warn().Err(err).Msg("token: failed to bind request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		utility.Logger.Info().Str("client_id", req.ClientID).Str("grant_type", req.GrantTypes).Msg("token: exchange requested")

		start := time.Now()
		opaqueToken, err := authHandler.RetrieveAccessToken(c.Request.Context(), req)
		duration := time.Since(start)

		if err != nil {
			utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Dur("duration_ms", duration).Msg("token: exchange failed")
			metrics.RecordTokenExchange(c.Request.Context(), duration, false)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}

		utility.Logger.Info().Str("client_id", req.ClientID).Dur("duration_ms", duration).Msg("token: exchange successful")
		metrics.RecordTokenExchange(c.Request.Context(), duration, true)
		c.JSON(http.StatusOK, opaqueToken)
	}
}

// refreshHandler: client → Proxy
func refreshHandler(authHandler auth.Service) gin.HandlerFunc {
	type refreshRequest struct {
		RefreshToken string `json:"refresh_token" form:"refresh_token"`
	}

	return func(c *gin.Context) {
		metrics := c.Request.Context().Value(metricsKey).(*telemetry.Metrics)
		req := &refreshRequest{}
		if err := c.Bind(req); err != nil {
			utility.Logger.Warn().Err(err).Msg("refresh: failed to bind request")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		if req.RefreshToken == "" {
			utility.Logger.Warn().Msg("refresh: missing refresh_token")
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "refresh_token is required"})
			return
		}

		utility.Logger.Info().Msg("refresh: token refresh requested")

		start := time.Now()
		opaqueToken, err := authHandler.RefreshToken(c.Request.Context(), req.RefreshToken)
		duration := time.Since(start)

		if err != nil {
			utility.Logger.Error().Err(err).Dur("duration_ms", duration).Msg("refresh: token refresh failed")
			metrics.RecordTokenExchange(c.Request.Context(), duration, false)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant"})
			return
		}

		utility.Logger.Info().Dur("duration_ms", duration).Msg("refresh: token refresh successful")
		metrics.RecordTokenExchange(c.Request.Context(), duration, true)
		c.JSON(http.StatusOK, opaqueToken)
	}
}

func registerHandler(authHandler auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		metrics := c.Request.Context().Value(metricsKey).(*telemetry.Metrics)
		req := &auth.RegisterRequest{}
		if err := json.NewDecoder(c.Request.Body).Decode(req); err != nil {
			utility.Logger.Warn().Err(err).Msg("register: failed to decode request body")
			metrics.RecordClientRegistration(c.Request.Context(), false)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
			return
		}

		utility.Logger.Info().Any("register_request", req).Msg("register: client registration requested")

		res, err := authHandler.RegisterClient(c.Request.Context(), req)

		if err != nil {
			utility.Logger.Error().Err(err).Msg("register: client registration failed")
			metrics.RecordClientRegistration(c.Request.Context(), false)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
			return
		}

		utility.Logger.Info().Str("client_id", res.ClientID).Msg("register: client registered successfully")
		metrics.RecordClientRegistration(c.Request.Context(), true)
		c.JSON(http.StatusCreated, res)
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
