package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		}
		key, err := cfg.EncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, byte(0x01), key[0])
		assert.Equal(t, byte(0x23), key[1])
	})

	t.Run("nil config", func(t *testing.T) {
		var cfg *Config
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("empty master key", func(t *testing.T) {
		cfg := &Config{}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("invalid hex characters", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not valid hex")
	})

	t.Run("too short", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
		assert.Contains(t, err.Error(), "got 8 bytes")
	})

	t.Run("too long", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
		assert.Contains(t, err.Error(), "got 33 bytes")
	})

	t.Run("odd number of hex chars", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
	})
}

// --- TestLoad ---

// writeConfigFile creates a temp dir with a config.yaml and returns the dir path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(content), 0644)
	require.NoError(t, err)
	return dir
}

// resetViperAndChdir resets viper state and changes to dir. Returns a cleanup function.
func resetViperAndChdir(t *testing.T, dir string) {
	t.Helper()
	viper.Reset()

	origDir, err := os.Getwd()
	require.NoError(t, err)
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() {
		os.Chdir(origDir)
		viper.Reset()
	})
}

const minimalConfig = `
proxy:
  base_url: http://localhost:8080
  listen_addr: ":8080"
idp:
  client_id: test-client
  client_secret: test-secret
  openid_configuration_url: https://auth.example.com/.well-known/openid-configuration
  scopes:
    - openid
  claims_mapping:
    sub: X-Sub
encryption:
  master_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
upstream:
  name: test-server
  resource: https://mcp.example.com
  base_url: https://mcp.example.com
  path_prefix: /mcp
`

func TestLoad(t *testing.T) {
	t.Run("valid config file", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "http://localhost:8080", cfg.Proxy.BaseURL)
		assert.Equal(t, ":8080", cfg.Proxy.ListenAddr)
		assert.Equal(t, "test-client", cfg.IDP.ClientID)
		assert.Equal(t, "test-secret", cfg.IDP.ClientSecret)
		assert.Equal(t, []string{"openid"}, cfg.IDP.Scopes)
		assert.Equal(t, "X-Sub", cfg.IDP.ClaimsMapping["sub"])
		assert.Equal(t, "test-server", cfg.Upstream.Name)
		assert.Equal(t, "https://mcp.example.com", cfg.Upstream.BaseURL)
		assert.Equal(t, "/mcp", cfg.Upstream.PathPrefix)
	})

	t.Run("defaults applied", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "error", cfg.Proxy.LogLevel)
		assert.Equal(t, "json", cfg.Proxy.LogFormat)
		assert.Equal(t, true, cfg.Telemetry.Enabled)
		assert.Equal(t, "mcp-proxy", cfg.Telemetry.ServiceName)
		assert.Equal(t, "1.0.0", cfg.Telemetry.ServiceVersion)
		assert.Equal(t, "localhost:4317", cfg.Telemetry.OTLPEndpoint)
	})

	t.Run("env var overrides client secret", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)
		t.Setenv("MCP_IDP_CLIENT_SECRET", "env-secret-override")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "env-secret-override", cfg.IDP.ClientSecret)
	})

	t.Run("env var overrides proxy base url", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)
		t.Setenv("MCP_PROXY_BASE_URL", "https://proxy.prod.example.com")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, "https://proxy.prod.example.com", cfg.Proxy.BaseURL)
	})

	t.Run("env var overrides listen addr", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)
		t.Setenv("MCP_LISTEN_ADDR", ":9090")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, ":9090", cfg.Proxy.ListenAddr)
	})

	t.Run("env var overrides telemetry enabled", func(t *testing.T) {
		dir := writeConfigFile(t, minimalConfig)
		resetViperAndChdir(t, dir)
		t.Setenv("MCP_TELEMETRY_ENABLED", "false")

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, false, cfg.Telemetry.Enabled)
	})

	t.Run("missing config file", func(t *testing.T) {
		dir := t.TempDir() // empty dir, no config.yaml
		resetViperAndChdir(t, dir)

		_, err := Load()
		assert.Error(t, err)
	})

	t.Run("invalid yaml", func(t *testing.T) {
		dir := writeConfigFile(t, "{{invalid yaml content")
		resetViperAndChdir(t, dir)

		_, err := Load()
		assert.Error(t, err)
	})

	t.Run("telemetry overrides from yaml", func(t *testing.T) {
		yamlContent := minimalConfig + `
telemetry:
  enabled: false
  service_name: custom-svc
  service_version: 2.0.0
  otlp_endpoint: otel.example.com:4318
`
		dir := writeConfigFile(t, yamlContent)
		resetViperAndChdir(t, dir)

		cfg, err := Load()
		require.NoError(t, err)

		assert.Equal(t, false, cfg.Telemetry.Enabled)
		assert.Equal(t, "custom-svc", cfg.Telemetry.ServiceName)
		assert.Equal(t, "2.0.0", cfg.Telemetry.ServiceVersion)
		assert.Equal(t, "otel.example.com:4318", cfg.Telemetry.OTLPEndpoint)
	})
}
