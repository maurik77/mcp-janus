// cmd/proxy/main.go
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"mcpproxy/internal/auth"
	"mcpproxy/internal/config"
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
func ginHandler(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

// ginWrap wraps standard http.HandlerFunc for Gin
func ginWrap(h http.HandlerFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		h(c.Writer, c.Request)
	}
}

// ginAuthMiddleware wraps the auth middleware for Gin
func ginAuthMiddleware(cfg *config.Config, key [32]byte) gin.HandlerFunc {
	middleware := server.AuthMiddleware(cfg, key)
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

	// Chiave di cifratura
	if len(cfg.Encryption.MasterKey) != 64 {
		log.Fatal("encryption.master_key must be 64 hex chars (32 bytes)")
	}
	keyBytes, _ := hex.DecodeString(cfg.Encryption.MasterKey)
	copy(encKey[:], keyBytes)

	// Config OAuth2 per IdP reale
	oauthConfig = &oauth2.Config{
		ClientID:     cfg.IDP.ClientID,
		ClientSecret: cfg.IDP.ClientSecret,
		RedirectURL:  cfg.Proxy.BaseURL + "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  cfg.IDP.AuthorizationEndpoint,
			TokenURL: cfg.IDP.TokenEndpoint,
		},
		Scopes: []string{"openid", "mcp"},
	}

	// Set Gin mode based on environment
	if os.Getenv("GIN_MODE") == "" {
		gin.SetMode(gin.ReleaseMode)
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
	r.GET("/.well-known/openid-configuration", ginHandler(server.OpenIDConfigurationHandler(cfg)))
	r.GET("/.well-known/oauth-protected-resource", ginHandler(server.ProtectedResourceMetadataHandler(cfg)))

	// Dynamic Client Registration
	r.POST("/register", func(c *gin.Context) {
		auth.RegisterHandler(c.Writer, c.Request, cfg, encKey)
	})

	// Authorization Code Flow
	r.GET("/auth", ginWrap(authHandler))
	r.GET("/callback", ginWrap(callbackHandler))
	r.POST("/token", ginWrap(tokenHandler))
	r.POST("/refresh", ginWrap(refreshHandler))

	// Proxy API - with auth middleware
	authorized := r.Group("/mcp")
	authorized.Use(ginAuthMiddleware(cfg, encKey))
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
		log.Printf("Upstreams: %d configured", len(cfg.Upstreams))
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
func authHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	resource := r.URL.Query().Get("resource")
	state := r.URL.Query().Get("state")

	if clientID == "" || resource == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Decrypt client_id to get redirect_uri
	clientData, err := auth.Decrypt(strings.TrimPrefix(clientID, "cli_"), encKey)
	if err != nil {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}

	var clientInfo struct {
		RedirectURI string `json:"r"`
	}
	if err := json.Unmarshal(clientData, &clientInfo); err != nil {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}

	// Generate PKCE
	verifier, challenge := auth.GeneratePKCE()

	// Create encrypted code (stateless)
	codePayload := auth.PKCECode{
		CodeVerifier: verifier,
		ClientID:     clientID,
		Resource:     resource,
		State:        state,
		ExpiresAt:    time.Now().Add(10 * time.Minute).Unix(),
	}
	codeJSON, _ := json.Marshal(codePayload)
	encryptedCode, _ := auth.Encrypt(codeJSON, encKey)

	// Redirect to real IdP
	authURL := oauthConfig.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("resource", resource),
		oauth2.SetAuthURLParam("redirect_uri", cfg.Proxy.BaseURL+"/callback"),
		oauth2.SetAuthURLParam("code", encryptedCode), // Pass encrypted code
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// callbackHandler: IdP → Proxy
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// In real flow, IdP redirects here with code
	// For stateless, we expect client to call /token directly
	http.Error(w, "Use /token endpoint", http.StatusBadRequest)
}

// tokenHandler: client → Proxy
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")

	if code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Decrypt code
	data, err := auth.Decrypt(code, encKey)
	if err != nil {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	var pkce auth.PKCECode
	if err := json.Unmarshal(data, &pkce); err != nil {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}

	if time.Now().Unix() > pkce.ExpiresAt {
		http.Error(w, `{"error":"expired_code"}`, http.StatusBadRequest)
		return
	}

	// Exchange with real IdP
	token, err := oauthConfig.Exchange(
		context.Background(),
		"", // code is in encrypted payload
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
		oauth2.SetAuthURLParam("code_verifier", pkce.CodeVerifier),
		oauth2.SetAuthURLParam("resource", pkce.Resource),
	)
	if err != nil {
		http.Error(w, `{"error":"token_exchange_failed"}`, http.StatusInternalServerError)
		return
	}

	// Create opaque token
	opaque := auth.OpaqueToken{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		Resource:     pkce.Resource,
		ClientID:     pkce.ClientID,
		ExpiresAt:    time.Now().Add(time.Duration(token.ExpiresIn) * time.Second).Unix(),
	}
	opaqueJSON, _ := json.Marshal(opaque)
	opaqueToken, _ := auth.Encrypt(opaqueJSON, encKey)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"access_token": "tok_" + opaqueToken,
		"token_type":   "Bearer",
		"expires_in":   token.ExpiresIn,
	})
}

// refreshHandler
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: implement refresh using encrypted refresh token
	http.Error(w, `{"error":"not_implemented"}`, http.StatusNotImplemented)
}
