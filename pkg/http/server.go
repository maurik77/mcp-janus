package http
package http

import (
	"log/slog"
	"net/http"

	"mcpproxy/internal/config"
	"mcpproxy/internal/crypto"
	"mcpproxy/internal/mcp"
	"mcpproxy/internal/oauth"
	"mcpproxy/internal/tokens"
)

// ServerDependencies holds all dependencies for the HTTP server
type ServerDependencies struct {
	CryptoService      crypto.CryptoService
	TokenStore         tokens.TokenStore
	OpaqueTokenService tokens.OpaqueTokenService
	OAuthProvider      oauth.OAuthProvider
	MCPClient          mcp.MCPClient
}

// Server represents the HTTP server
type Server struct {
	cfg  *config.Config
	deps ServerDependencies
	mux  *http.ServeMux
}

// NewServer creates a new HTTP server
func NewServer(cfg *config.Config, deps ServerDependencies) *Server {
	s := &Server{
		cfg:  cfg,
		deps: deps,
		mux:  http.NewServeMux(),
	}

	s.registerRoutes()
	return s
}

// registerRoutes registers all HTTP routes
func (s *Server) registerRoutes() {
	// OAuth / Protected Resource Metadata endpoints
	s.mux.HandleFunc("/.well-known/oauth-protected-resource", s.handleProtectedResourceMetadata)
	s.mux.HandleFunc("/auth/authorize", s.handleAuthorize)
	s.mux.HandleFunc("/auth/callback", s.handleCallback)
	s.mux.HandleFunc("/token", s.handleToken)

	// Health check
	s.mux.HandleFunc("/health", s.handleHealth)

	// MCP proxy endpoints (catch-all, requires authentication)
	s.mux.HandleFunc("/", s.handleMCPProxy)
}

// Handler returns the HTTP handler with middleware
func (s *Server) Handler() http.Handler {
	handler := s.mux

	// Apply middleware (in reverse order of execution)
	handler = s.middlewareLogging(handler)
	handler = s.middlewareHTTPSEnforcement(handler)

	return handler
}

// handleProtectedResourceMetadata implements RFC 9728
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := map[string]interface{}{
		"resource": s.cfg.ProxyURL,
		"authorization_servers": []string{
			s.cfg.ProxyURL + "/auth",
		},
		"bearer_methods_supported": []string{"header"},
		"resource_documentation":   s.cfg.ProxyURL + "/docs",
	}

	w.Header().Set("Content-Type", "application/json")
	if err := writeJSON(w, metadata); err != nil {
		slog.Error("failed to write metadata", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

// handleAuthorize initiates OAuth flow
func (s *Server) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement OAuth authorization endpoint
	// This would handle client authorization requests and redirect to upstream AS
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleCallback handles OAuth callback
func (s *Server) handleCallback(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement OAuth callback handler
	// This receives the authorization code from upstream AS and exchanges it
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleToken issues opaque tokens
func (s *Server) handleToken(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement token endpoint
	// This exchanges authorization codes for opaque bearer tokens
	http.Error(w, "Not implemented", http.StatusNotImplemented)
}

// handleHealth is a health check endpoint
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

// handleMCPProxy forwards authenticated MCP requests
func (s *Server) handleMCPProxy(w http.ResponseWriter, r *http.Request) {
	// Skip authentication for well-known endpoints
	if r.URL.Path == "/.well-known/oauth-protected-resource" ||
		r.URL.Path == "/auth/authorize" ||
		r.URL.Path == "/auth/callback" ||
		r.URL.Path == "/token" ||
		r.URL.Path == "/health" {
		return
	}

	// Extract and validate opaque token
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		s.sendUnauthorized(w, "Authorization required")
		return
	}

	// Parse Bearer token
	token := extractBearerToken(authHeader)
	if token == "" {
		s.sendUnauthorized(w, "Invalid authorization header")
		return
	}

	// Validate opaque token
	payload, err := s.deps.OpaqueTokenService.Validate(r.Context(), token)
	if err != nil {
		slog.Warn("token validation failed", "error", err)
		s.sendUnauthorized(w, "Invalid or expired token")
		return
	}

	// Retrieve upstream credentials
	creds, err := s.deps.TokenStore.Retrieve(r.Context(), payload.RTID)
	if err != nil {
		slog.Error("failed to retrieve upstream credentials", "rtid", payload.RTID, "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Check if upstream token needs refresh
	if creds.IsExpired() {
		slog.Warn("upstream token expired", "rtid", payload.RTID)
		http.Error(w, "Upstream token expired", http.StatusUnauthorized)
		return
	}

	// Read request body
	body, err := readBody(r)
	if err != nil {
		slog.Error("failed to read request body", "error", err)
		http.Error(w, "Failed to read request", http.StatusBadRequest)
		return
	}

	// Forward to upstream MCP server
	proxyReq := &mcp.ProxyRequest{
		Method:        r.Method,
		Path:          r.URL.Path,
		Headers:       r.Header,
		Body:          body,
		UpstreamToken: creds.AccessToken,
		UpstreamURL:   s.cfg.UpstreamMCPURL,
	}

	proxyResp, err := s.deps.MCPClient.Forward(r.Context(), proxyReq)
	if err != nil {
		slog.Error("failed to forward request", "error", err)
		http.Error(w, "Failed to forward request", http.StatusBadGateway)
		return
	}

	// Copy response headers
	for key, values := range proxyResp.Headers {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Write response
	w.WriteHeader(proxyResp.StatusCode)
	w.Write(proxyResp.Body)
}

// sendUnauthorized sends a 401 response with WWW-Authenticate header
func (s *Server) sendUnauthorized(w http.ResponseWriter, message string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="`+s.cfg.ProxyURL+`", error="invalid_token"`)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	writeJSON(w, map[string]string{
		"error":             "invalid_token",
		"error_description": message,
	})
}
