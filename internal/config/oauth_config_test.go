package config

import (
	"os"
	"testing"
	"time"
)

func TestConfig_OAuthClientCredentials(t *testing.T) {
	// Test that OAuth credentials can be loaded
	os.Setenv("PROXY_URL", "https://proxy.example.com")
	os.Setenv("UPSTREAM_MCP_URL", "https://mcp.example.com")
	os.Setenv("OAUTH_CLIENT_ID", "test-client-id")
	os.Setenv("OAUTH_CLIENT_SECRET", "test-client-secret")
	os.Setenv("OAUTH_TOKEN_URL", "https://idp.example.com/token")
	os.Setenv("OAUTH_AUTH_URL", "https://idp.example.com/authorize")
	defer func() {
		os.Unsetenv("PROXY_URL")
		os.Unsetenv("UPSTREAM_MCP_URL")
		os.Unsetenv("OAUTH_CLIENT_ID")
		os.Unsetenv("OAUTH_CLIENT_SECRET")
		os.Unsetenv("OAUTH_TOKEN_URL")
		os.Unsetenv("OAUTH_AUTH_URL")
	}()

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed: %v", err)
	}

	if cfg.OAuthClientID != "test-client-id" {
		t.Errorf("Expected OAuthClientID 'test-client-id', got '%s'", cfg.OAuthClientID)
	}

	if cfg.OAuthClientSecret != "test-client-secret" {
		t.Errorf("Expected OAuthClientSecret 'test-client-secret', got '%s'", cfg.OAuthClientSecret)
	}

	if cfg.OAuthTokenURL != "https://idp.example.com/token" {
		t.Errorf("Expected OAuthTokenURL 'https://idp.example.com/token', got '%s'", cfg.OAuthTokenURL)
	}

	if cfg.OAuthAuthURL != "https://idp.example.com/authorize" {
		t.Errorf("Expected OAuthAuthURL 'https://idp.example.com/authorize', got '%s'", cfg.OAuthAuthURL)
	}

	// Test validation passes with complete OAuth config
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validation failed with valid OAuth config: %v", err)
	}
}

func TestConfig_OAuthValidation_MissingClientID(t *testing.T) {
	cfg := &Config{
		ProxyURL:          "https://proxy.example.com",
		UpstreamMCPURL:    "https://mcp.example.com",
		OpaqueTokenTTL:    15 * time.Minute,
		ShutdownTimeout:   30 * time.Second,
		KeyStoreType:      "memory",
		OAuthTokenURL:     "https://idp.example.com/token",
		OAuthClientSecret: "secret",
		// Missing OAuthClientID
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing OAUTH_CLIENT_ID, got nil")
	}
}

func TestConfig_OAuthValidation_MissingClientSecret(t *testing.T) {
	cfg := &Config{
		ProxyURL:        "https://proxy.example.com",
		UpstreamMCPURL:  "https://mcp.example.com",
		OpaqueTokenTTL:  15 * time.Minute,
		ShutdownTimeout: 30 * time.Second,
		KeyStoreType:    "memory",
		OAuthTokenURL:   "https://idp.example.com/token",
		OAuthClientID:   "client-id",
		// Missing OAuthClientSecret
	}

	err := cfg.Validate()
	if err == nil {
		t.Error("Expected validation error for missing OAUTH_CLIENT_SECRET, got nil")
	}
}

func TestConfig_ResourceMetadataURL_DefaultValue(t *testing.T) {
	os.Setenv("PROXY_URL", "https://proxy.example.com")
	os.Setenv("UPSTREAM_MCP_URL", "https://mcp.example.com")
	defer func() {
		os.Unsetenv("PROXY_URL")
		os.Unsetenv("UPSTREAM_MCP_URL")
	}()

	cfg, err := LoadFromEnv()
	if err != nil {
		t.Fatalf("LoadFromEnv failed: %v", err)
	}

	expectedURL := "https://proxy.example.com/.well-known/oauth-protected-resource"
	if cfg.ResourceMetadataURL != expectedURL {
		t.Errorf("Expected ResourceMetadataURL '%s', got '%s'", expectedURL, cfg.ResourceMetadataURL)
	}
}
