package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds all configuration for the proxy
type Config struct {
	// Server config
	ListenAddr      string        // :8080
	TLSCertFile     string        // path to cert
	TLSKeyFile      string        // path to key
	ShutdownTimeout time.Duration // 30s

	// Proxy identity
	ProxyURL string // https://proxy.example.com

	// Resource metadata URL for WWW-Authenticate header
	ResourceMetadataURL string // https://proxy.example.com/.well-known/oauth-protected-resource

	// Upstream MCP server
	UpstreamMCPURL string // https://mcp.example.com

	// OAuth Client Credentials (proxy acts as OAuth client)
	OAuthClientID     string // Client ID for authenticating with IDP
	OAuthClientSecret string // Client secret for authenticating with IDP
	OAuthTokenURL     string // Token endpoint of the IDP
	OAuthAuthURL      string // Authorization endpoint of the IDP

	// Token settings
	OpaqueTokenTTL time.Duration // 15 minutes

	// Crypto settings
	KeyStoreType string // "memory", "file", "kms"
	KeyStorePath string // path for file-based keys

	// Rate limiting
	RateLimitEnabled bool
	RateLimitRPS     int
	RateLimitBurst   int

	// Logging
	LogLevel  string // "info", "debug", "error"
	LogFormat string // "json", "text"
}

// Validate checks configuration
func (c *Config) Validate() error {
	if c.ProxyURL == "" {
		return fmt.Errorf("PROXY_URL is required")
	}

	if c.UpstreamMCPURL == "" {
		return fmt.Errorf("UPSTREAM_MCP_URL is required")
	}

	if c.OpaqueTokenTTL <= 0 {
		return fmt.Errorf("OPAQUE_TOKEN_TTL must be positive")
	}

	if c.ShutdownTimeout <= 0 {
		return fmt.Errorf("SHUTDOWN_TIMEOUT must be positive")
	}

	if c.KeyStoreType != "memory" && c.KeyStoreType != "file" && c.KeyStoreType != "kms" {
		return fmt.Errorf("KEY_STORE_TYPE must be one of: memory, file, kms")
	}

	if c.KeyStoreType == "file" && c.KeyStorePath == "" {
		return fmt.Errorf("KEY_STORE_PATH is required when KEY_STORE_TYPE is file")
	}

	// Validate OAuth credentials if token URL is provided
	if c.OAuthTokenURL != "" {
		if c.OAuthClientID == "" {
			return fmt.Errorf("OAUTH_CLIENT_ID is required when OAUTH_TOKEN_URL is configured")
		}
		if c.OAuthClientSecret == "" {
			return fmt.Errorf("OAUTH_CLIENT_SECRET is required when OAUTH_TOKEN_URL is configured")
		}
	}

	return nil
}

// LoadFromEnv loads config from environment variables
func LoadFromEnv() (*Config, error) {
	cfg := &Config{
		ListenAddr:      getEnv("LISTEN_ADDR", ":8443"),
		TLSCertFile:     getEnv("TLS_CERT_FILE", ""),
		TLSKeyFile:      getEnv("TLS_KEY_FILE", ""),
		ShutdownTimeout: getDurationEnv("SHUTDOWN_TIMEOUT", 30*time.Second),

		ProxyURL:            getEnv("PROXY_URL", ""),
		ResourceMetadataURL: getEnv("RESOURCE_METADATA_URL", ""),
		UpstreamMCPURL:      getEnv("UPSTREAM_MCP_URL", ""),

		OAuthClientID:     getEnv("OAUTH_CLIENT_ID", ""),
		OAuthClientSecret: getEnv("OAUTH_CLIENT_SECRET", ""),
		OAuthTokenURL:     getEnv("OAUTH_TOKEN_URL", ""),
		OAuthAuthURL:      getEnv("OAUTH_AUTH_URL", ""),

		OpaqueTokenTTL: getDurationEnv("OPAQUE_TOKEN_TTL", 15*time.Minute),

		KeyStoreType: getEnv("KEY_STORE_TYPE", "memory"),
		KeyStorePath: getEnv("KEY_STORE_PATH", ""),

		RateLimitEnabled: getBoolEnv("RATE_LIMIT_ENABLED", true),
		RateLimitRPS:     getIntEnv("RATE_LIMIT_RPS", 100),
		RateLimitBurst:   getIntEnv("RATE_LIMIT_BURST", 200),

		LogLevel:  getEnv("LOG_LEVEL", "info"),
		LogFormat: getEnv("LOG_FORMAT", "json"),
	}

	// Set default resource metadata URL if not provided
	if cfg.ResourceMetadataURL == "" && cfg.ProxyURL != "" {
		cfg.ResourceMetadataURL = cfg.ProxyURL + "/.well-known/oauth-protected-resource"
	}

	return cfg, nil
}

// getEnv retrieves an environment variable with a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getIntEnv retrieves an integer environment variable with a default value
func getIntEnv(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intVal, err := strconv.Atoi(value); err == nil {
			return intVal
		}
	}
	return defaultValue
}

// getBoolEnv retrieves a boolean environment variable with a default value
func getBoolEnv(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolVal, err := strconv.ParseBool(value); err == nil {
			return boolVal
		}
	}
	return defaultValue
}

// getDurationEnv retrieves a duration environment variable with a default value
func getDurationEnv(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}
