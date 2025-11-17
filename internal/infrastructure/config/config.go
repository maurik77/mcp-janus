// internal/config/config.go
package config

import (
	"encoding/hex"

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
}

type Proxy struct {
	BaseURL     string `mapstructure:"base_url"`
	ListenAddr  string `mapstructure:"listen_addr"`
	TLS         bool   `mapstructure:"tls"`
	TLSCertFile string `mapstructure:"tls_cert_file"`
	TLSKeyFile  string `mapstructure:"tls_key_file"`
}

type Config struct {
	Proxy      Proxy `mapstructure:"proxy"`
	IDP        IDP   `mapstructure:"idp"`
	Encryption struct {
		MasterKey string `mapstructure:"master_key"`
	} `mapstructure:"encryption"`
	Upstream Upstream `mapstructure:"upstream"`
}

func (c *Config) EncryptionKey() [32]byte {
	var encKey [32]byte

	if c == nil || c.Encryption.MasterKey == "" {
		return encKey
	}

	keyBytes, _ := hex.DecodeString(c.Encryption.MasterKey)
	copy(encKey[:], keyBytes)
	return encKey
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

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
	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
