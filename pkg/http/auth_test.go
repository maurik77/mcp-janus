package http

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"mcpproxy/internal/config"
)

func TestUnauthorizedResponse_ContainsResourceMetadataURL(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:            "https://proxy.example.com",
		ResourceMetadataURL: "https://proxy.example.com/.well-known/oauth-protected-resource",
		UpstreamMCPURL:      "https://mcp.example.com",
		OpaqueTokenTTL:      15,
	}

	deps := ServerDependencies{
		CryptoService:      nil,
		TokenStore:         nil,
		OpaqueTokenService: nil,
		OAuthProvider:      nil,
		MCPClient:          nil,
	}

	server := NewServer(cfg, deps)

	// Create a test request without authorization header
	req := httptest.NewRequest(http.MethodGet, "/some-mcp-endpoint", nil)
	w := httptest.NewRecorder()

	// Call the MCP proxy handler
	server.handleMCPProxy(w, req)

	// Check status code
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	// Check WWW-Authenticate header
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if wwwAuth == "" {
		t.Fatal("WWW-Authenticate header is missing")
	}

	// Verify it contains resource_metadata_url
	if !strings.Contains(wwwAuth, "resource_metadata_url=") {
		t.Errorf("WWW-Authenticate header missing resource_metadata_url: %s", wwwAuth)
	}

	// Verify it contains the correct URL
	expectedURL := cfg.ResourceMetadataURL
	if !strings.Contains(wwwAuth, expectedURL) {
		t.Errorf("WWW-Authenticate header doesn't contain expected URL %s: %s", expectedURL, wwwAuth)
	}

	// Verify it contains realm
	if !strings.Contains(wwwAuth, `realm="https://proxy.example.com"`) {
		t.Errorf("WWW-Authenticate header missing realm: %s", wwwAuth)
	}

	// Verify it contains error
	if !strings.Contains(wwwAuth, `error="invalid_token"`) {
		t.Errorf("WWW-Authenticate header missing error: %s", wwwAuth)
	}
}

func TestUnauthorizedResponse_WithInvalidToken(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:            "https://proxy.example.com",
		ResourceMetadataURL: "https://proxy.example.com/.well-known/oauth-protected-resource",
		UpstreamMCPURL:      "https://mcp.example.com",
		OpaqueTokenTTL:      15,
	}

	deps := ServerDependencies{
		CryptoService:      nil,
		TokenStore:         nil,
		OpaqueTokenService: nil,
		OAuthProvider:      nil,
		MCPClient:          nil,
	}

	server := NewServer(cfg, deps)

	// Create a test request with invalid authorization header
	req := httptest.NewRequest(http.MethodGet, "/some-mcp-endpoint", nil)
	req.Header.Set("Authorization", "InvalidFormat")
	w := httptest.NewRecorder()

	// Call the MCP proxy handler
	server.handleMCPProxy(w, req)

	// Check status code
	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401, got %d", w.Code)
	}

	// Check WWW-Authenticate header contains resource metadata URL
	wwwAuth := w.Header().Get("WWW-Authenticate")
	if !strings.Contains(wwwAuth, cfg.ResourceMetadataURL) {
		t.Errorf("WWW-Authenticate header doesn't contain resource metadata URL: %s", wwwAuth)
	}
}

func TestResourceMetadataEndpoint(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:            "https://proxy.example.com",
		ResourceMetadataURL: "https://proxy.example.com/.well-known/oauth-protected-resource",
		UpstreamMCPURL:      "https://mcp.example.com",
	}

	deps := ServerDependencies{
		CryptoService:      nil,
		TokenStore:         nil,
		OpaqueTokenService: nil,
		OAuthProvider:      nil,
		MCPClient:          nil,
	}

	server := NewServer(cfg, deps)

	req := httptest.NewRequest(http.MethodGet, "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	// Call the handler
	server.handleProtectedResourceMetadata(w, req)

	// Check status code
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}

	// Check Content-Type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Check body contains resource URL
	body := w.Body.String()
	if !strings.Contains(body, cfg.ProxyURL) {
		t.Errorf("Response doesn't contain proxy URL: %s", body)
	}
}
