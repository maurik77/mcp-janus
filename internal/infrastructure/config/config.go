// internal/config/config.go
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"time"

	"github.com/spf13/viper"
)

type Upstream struct {
	Name       string `mapstructure:"name"`
	Resource   string `mapstructure:"resource"`
	BaseURL    string `mapstructure:"base_url"`
	PathPrefix string `mapstructure:"path_prefix"`
}

type IDP struct {
	ClientID               string            `mapstructure:"client_id"`
	ClientSecret           string            `mapstructure:"client_secret"`
	OpenIDConfigurationURL string            `mapstructure:"openid_configuration_url"`
	Scopes                 []string          `mapstructure:"scopes"`
	ClaimsMapping          map[string]string `mapstructure:"claims_mapping"`
	FixedHeaders           map[string]string `mapstructure:"fixed_headers"`
	JWTLeeway              time.Duration     `mapstructure:"jwt_leeway"`
	SkipTLSVerify          bool              `mapstructure:"skip_tls_verify"`
	FetchRetryAttempts     int               `mapstructure:"fetch_retry_attempts"`
	FetchRetryDelay        time.Duration     `mapstructure:"fetch_retry_delay"`
}

type CORS struct {
	Enabled          bool          `mapstructure:"enabled"`
	AllowedOrigins   []string      `mapstructure:"allowed_origins"`
	AllowedMethods   []string      `mapstructure:"allowed_methods"`
	AllowedHeaders   []string      `mapstructure:"allowed_headers"`
	ExposedHeaders   []string      `mapstructure:"exposed_headers"`
	AllowCredentials bool          `mapstructure:"allow_credentials"`
	MaxAge           time.Duration `mapstructure:"max_age"`
}

type Proxy struct {
	Issuer      string `mapstructure:"issuer"`
	BaseURL     string `mapstructure:"base_url"`
	ListenAddr  string `mapstructure:"listen_addr"`
	ProbeAddr   string `mapstructure:"probe_addr"`
	TLS         bool   `mapstructure:"tls"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
	LogLevel    string `mapstructure:"log_level"`
	LogFormat   string `mapstructure:"log_format"`
	CORS        CORS   `mapstructure:"cors"`
}

type Telemetry struct {
	Enabled        bool   `mapstructure:"enabled"`
	ServiceName    string `mapstructure:"service_name"`
	ServiceVersion string `mapstructure:"service_version"`
	OTLPEndpoint   string `mapstructure:"otlp_endpoint"`
}

type Config struct {
	Proxy      Proxy `mapstructure:"proxy"`
	IDP        IDP   `mapstructure:"idp"`
	Encryption struct {
		MasterKey string `mapstructure:"master_key"`
	} `mapstructure:"encryption"`
	Upstream  Upstream  `mapstructure:"upstream"`
	Telemetry Telemetry `mapstructure:"telemetry"`
}

func (c *Config) EncryptionKey() ([32]byte, error) {
	var encKey [32]byte

	if c == nil || c.Encryption.MasterKey == "" {
		return encKey, fmt.Errorf("encryption master_key is not configured")
	}

	keyBytes, err := hex.DecodeString(c.Encryption.MasterKey)
	if err != nil {
		return encKey, fmt.Errorf("encryption master_key is not valid hex: %w", err)
	}

	if len(keyBytes) != 32 {
		return encKey, fmt.Errorf("encryption master_key must be exactly 32 bytes (64 hex chars), got %d bytes", len(keyBytes))
	}

	copy(encKey[:], keyBytes)
	return encKey, nil
}

func Load() (*Config, error) {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "."
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(configPath)

	viper.AutomaticEnv()
	viper.SetEnvPrefix("MCP")
	err := viper.BindEnv("proxy.base_url", "MCP_PROXY_BASE_URL")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("idp.client_secret", "MCP_IDP_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.listen_addr", "MCP_LISTEN_ADDR")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.probe_addr", "MCP_PROBE_ADDR")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.tls", "MCP_TLS")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.tls_cert_file", "MCP_TLS_CERT_FILE")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.tls_key_file", "MCP_TLS_KEY_FILE")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("telemetry.enabled", "MCP_TELEMETRY_ENABLED")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("telemetry.otlp_endpoint", "MCP_TELEMETRY_OTLP_ENDPOINT")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("encryption.master_key", "MCP_ENCRYPTION_MASTER_KEY")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("idp.skip_tls_verify", "MCP_IDP_SKIP_TLS_VERIFY")
	if err != nil {
		return nil, err
	}
	err = viper.BindEnv("proxy.cors.enabled", "MCP_PROXY_CORS_ENABLED")
	if err != nil {
		return nil, err
	}
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	viper.SetDefault("telemetry.otlp_endpoint", "localhost:4317")
	viper.SetDefault("telemetry.service_name", "mcp-proxy")
	viper.SetDefault("telemetry.service_version", "1.0.0")
	viper.SetDefault("telemetry.enabled", true)

	viper.SetDefault("proxy.probe_addr", ":2113")
	viper.SetDefault("proxy.log_level", "error")
	viper.SetDefault("proxy.log_format", "json")
	viper.SetDefault("idp.skip_tls_verify", false)

	viper.SetDefault("proxy.cors.enabled", false)
	viper.SetDefault("proxy.cors.allowed_methods",
		[]string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"})
	viper.SetDefault("proxy.cors.allowed_headers",
		[]string{"Authorization", "Content-Type", "Accept",
			"Mcp-Session-Id", "Mcp-Protocol-Version", "x-custom-auth-headers"})
	viper.SetDefault("proxy.cors.exposed_headers",
		[]string{"WWW-Authenticate", "Mcp-Session-Id"})
	viper.SetDefault("proxy.cors.max_age", 12*time.Hour)

	viper.SetDefault("idp.fetch_retry_attempts", 3)
	viper.SetDefault("idp.fetch_retry_delay", "2s")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
