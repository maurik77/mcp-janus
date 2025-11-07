// cmd/proxy/main.go
package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mcpproxy/internal/auth"
	"mcpproxy/internal/config"
	"mcpproxy/internal/server"
	"mcpproxy/internal/utility"

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
		Scopes: cfg.IDP.Scopes,
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
	r.POST("/register", ginWrap(registerHandler))

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

// authHandler: client → Proxy

func authHandler(w http.ResponseWriter, r *http.Request) {
	clientID := r.URL.Query().Get("client_id")
	state := r.URL.Query().Get("state")
	code_challenge := r.URL.Query().Get("code_challenge")
	redirect_uri := r.URL.Query().Get("redirect_uri")
	code_challenge_method := r.URL.Query().Get("code_challenge_method")

	if clientID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	clientData, err := auth.DecodeClientID(clientID, encKey)

	// print clientData for debugging
	fmt.Printf("Decoded client data: %+v\n", clientData)

	// Decrypt client_id to get redirect_uri
	if err != nil {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}

	stateData := auth.StateData{
		OriginalState: state,
		RedirectURI:   redirect_uri,
	}

	// Redirect to real IdP
	authURL := oauthConfig.AuthCodeURL(
		stateData.Encode(),
		oauth2.SetAuthURLParam("code_challenge", code_challenge),
		oauth2.SetAuthURLParam("code_challenge_method", code_challenge_method),
		oauth2.SetAuthURLParam("redirect_uri", cfg.Proxy.BaseURL+"/callback"),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
}

// callbackHandler: IdP → Proxy
func callbackHandler(w http.ResponseWriter, r *http.Request) {
	// Read state and code
	stateParam := r.URL.Query().Get("state")
	codeParam := r.URL.Query().Get("code")
	if stateParam == "" || codeParam == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Decode state
	stateData, err := auth.DecodeStateData(stateParam)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	// Redirect back to client with original state and code
	redirectURL, err := url.Parse(stateData.RedirectURI)
	if err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	query := redirectURL.Query()
	query.Set("code", codeParam)
	query.Set("state", stateData.OriginalState)
	redirectURL.RawQuery = query.Encode()

	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// tokenHandler: client → Proxy
func tokenHandler(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	code := r.FormValue("code")
	clientID := r.FormValue("client_id")
	codeVerifier := r.FormValue("code_verifier")
	clientSecret := r.FormValue("client_secret")

	if code == "" || clientID == "" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	clientData, err := auth.DecodeClientID(clientID, encKey)

	// print clientData for debugging
	fmt.Printf("Decoded client data in tokenHandler: %+v\n", clientData)

	if err != nil {
		http.Error(w, `{"error":"client_id_invalid"}`, http.StatusBadRequest)
		return
	}

	if clientData.Secret != clientSecret {
		http.Error(w, `{"error":"client_secret_invalid"}`, http.StatusBadRequest)
		return
	}

	// Exchange with real IdP
	token, err := oauthConfig.Exchange(
		context.Background(),
		code,
		oauth2.SetAuthURLParam("grant_type", "authorization_code"),
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)

	if err != nil {
		http.Error(w, `{"error":"token_exchange_failed"}`, http.StatusInternalServerError)
		return
	}

	opaqueToken := token
	opaqueToken.AccessToken, err = utility.Encrypt([]byte(token.AccessToken), encKey)

	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	opaqueToken.RefreshToken, err = utility.Encrypt([]byte(token.RefreshToken), encKey)

	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(opaqueToken)
}

// refreshHandler
func refreshHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: implement refresh using encrypted refresh token
	http.Error(w, `{"error":"not_implemented"}`, http.StatusNotImplemented)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req auth.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	clientId, secret, err := generateClientID(req, encKey)

	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	res := auth.RegisterResponse{
		ClientID:     clientId,
		ClientSecret: secret,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func generateClientID(req auth.RegisterRequest, key [32]byte) (string, string, error) {
	// For simplicity, we only store redirect_uris in encrypted client_id
	// Generate a random secret (in real case, should be more robust)
	secretBytes := make([]byte, 16)
	for i := range secretBytes {
		secretBytes[i] = byte(65 + i) // Simple deterministic for example
	}
	clientSecret := hex.EncodeToString(secretBytes)

	clientData := auth.ClientIdData{
		RedirectURIs: req.RedirectURIs,
		Secret:       clientSecret,
	}

	encryptedClientID, err := clientData.Encode(key)

	return encryptedClientID, clientSecret, err
}
