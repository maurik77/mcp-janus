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

type stateData struct {
	OriginalState string `json:"s"`
	RedirectURI   string `json:"e"`
}

func (s *stateData) Encode() string {
	// concatenate OriginalState and RedirectURI with a separator | and url encode
	encoded := url.QueryEscape(s.OriginalState + "|" + s.RedirectURI)
	return encoded
}

func DecodeStateData(encoded string) (*stateData, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 2)
	splitIndex := -1
	for i, c := range decoded {
		if c == '|' {
			splitIndex = i
			break
		}
	}
	if splitIndex == -1 {
		return nil, fmt.Errorf("invalid state data")
	}
	parts[0] = decoded[:splitIndex]
	parts[1] = decoded[splitIndex+1:]

	return &stateData{
		OriginalState: parts[0],
		RedirectURI:   parts[1],
	}, nil
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

	clientData, err := DecodeClientID(clientID, encKey)

	// print clientData for debugging
	fmt.Printf("Decoded client data: %+v\n", clientData)

	// Decrypt client_id to get redirect_uri
	if err != nil {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
		return
	}

	stateData := stateData{
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
	stateData, err := DecodeStateData(stateParam)
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
	json.NewEncoder(w).Encode(map[string]any{
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

type registerRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type registerResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type clientIdData struct {
	RedirectURIs []string `json:"r"`
	Secret       string   `json:"s"`
}

func (c *clientIdData) Encode(key [32]byte) (string, error) {
	dataJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encrypted, err := auth.Encrypt(dataJSON, key)
	if err != nil {
		return "", err
	}
	return encrypted, nil
}

func DecodeClientID(encrypted string, key [32]byte) (*clientIdData, error) {
	data, err := auth.Decrypt(encrypted, key)
	if err != nil {
		return nil, err
	}
	var cid clientIdData
	if err := json.Unmarshal(data, &cid); err != nil {
		return nil, err
	}
	return &cid, nil
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}

	clientId, secret, err := generateClientID(req, encKey)

	if err != nil {
		http.Error(w, `{"error":"server_error"}`, http.StatusInternalServerError)
		return
	}

	res := registerResponse{
		ClientID:     clientId,
		ClientSecret: secret,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(res)
}

func generateClientID(req registerRequest, key [32]byte) (string, string, error) {
	// For simplicity, we only store redirect_uris in encrypted client_id
	// Generate a random secret (in real case, should be more robust)
	secretBytes := make([]byte, 16)
	for i := range secretBytes {
		secretBytes[i] = byte(65 + i) // Simple deterministic for example
	}
	clientSecret := hex.EncodeToString(secretBytes)

	clientData := clientIdData{
		RedirectURIs: req.RedirectURIs,
		Secret:       clientSecret,
	}

	encryptedClientID, err := clientData.Encode(key)

	return encryptedClientID, clientSecret, err
}
