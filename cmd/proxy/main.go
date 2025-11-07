// cmd/proxy/main.go
package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mcpproxy/internal/auth"
	"mcpproxy/internal/config"
	"mcpproxy/internal/metadata"
	"mcpproxy/internal/server"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

var (
	cfg         *config.Config
	encKey      [32]byte
	oauthConfig *oauth2.Config
)

// ginHandler wraps http.HandlerFunc for Gin
func ginMetadataHandler(metadata func() any) gin.HandlerFunc {
	return func(c *gin.Context) {
		data := metadata()
		c.Header("Content-Type", "application/json")
		json.NewEncoder(c.Writer).Encode(data)
	}
}

// ginAuthMiddleware wraps the auth middleware for Gin
func ginAuthMiddleware(service metadata.Service) gin.HandlerFunc {
	middleware := server.AuthMiddleware(cfg, service, encKey)
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

func main() {
	// Carica configurazione
	var err error
	cfg, err = config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
	}

	authService, err := auth.New(*cfg)
	if err != nil {
		log.Fatalf("Failed to initialize auth handler: %v", err)
	}

	metadataService, err := metadata.New(*cfg)
	if err != nil {
		log.Fatalf("Failed to initialize metadata handler: %v", err)
	}

	// Router
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	// Custom timeout middleware
	r.Use(func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), 30*time.Second)
		defer cancel()
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
	authorized.Use(ginAuthMiddleware(metadataService))
	{
		authorized.Any("/*path", func(c *gin.Context) {
			server.ProxyHandler(c.Writer, c.Request)
		})
	}

	// Health
	r.GET("/health", func(c *gin.Context) {
		c.String(http.StatusOK, "OK")
	})

	// Avvio server
	srv := &http.Server{
		Addr:    cfg.Proxy.ListenAddr,
		Handler: r,
	}

	go func() {
		log.Printf("MCP Proxy Server starting on %s", cfg.Proxy.ListenAddr)
		log.Printf("Base URL: %s", cfg.Proxy.BaseURL)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped.")
}

// authHandler: client → Proxy

func authHandler(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &auth.AuthenticateRequest{}
		err := c.Bind(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}

		authURL, err := authService.AuthenticateRequest(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		http.Redirect(c.Writer, c.Request, authURL, http.StatusFound)
	}
}

// callbackHandler: IdP → Proxy
func callbackHandler(authService auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &auth.AuthorizationCodeData{}
		err := c.BindQuery(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}

		authData, redirectURL, err := authService.ManageAuthorizationCode(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}

		query := redirectURL.Query()
		query.Set("code", authData.Code)
		query.Set("state", authData.State)
		redirectURL.RawQuery = query.Encode()

		http.Redirect(c.Writer, c.Request, redirectURL.String(), http.StatusFound)
	}
}

// tokenHandler: client → Proxy
func tokenHandler(authHandler auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &auth.AccessTokenRequest{}
		err := c.Bind(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}

		opaqueToken, err := authHandler.RetrieveAccessToken(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		c.Writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(c.Writer).Encode(opaqueToken)
	}
}

// refreshHandler
func refreshHandler(_ auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		http.Error(c.Writer, `{"error":"not_implemented"}`, http.StatusNotImplemented)
	}
}

func registerHandler(authHandler auth.Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		req := &auth.RegisterRequest{}
		if err := json.NewDecoder(c.Request.Body).Decode(req); err != nil {
			http.Error(c.Writer, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}

		res, err := authHandler.RegisterClient(req)

		if err != nil {
			http.Error(c.Writer, `{"error":"server_error"}`, http.StatusInternalServerError)
			return
		}

		c.Writer.Header().Set("Content-Type", "application/json")
		json.NewEncoder(c.Writer).Encode(res)
	}
}
