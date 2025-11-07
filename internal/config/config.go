// internal/config/config.go
package config

import (
	"github.com/spf13/viper"
)

type Upstream struct {
	Name       string `mapstructure:"name"`
	Resource   string `mapstructure:"resource"`
	BaseURL    string `mapstructure:"base_url"`
	PathPrefix string `mapstructure:"path_prefix"`
}

type IDP struct {
	IssuerURL             string            `mapstructure:"issuer_url"`
	ClientID              string            `mapstructure:"client_id"`
	ClientSecret          string            `mapstructure:"client_secret"`
	AuthorizationEndpoint string            `mapstructure:"authorization_endpoint"`
	TokenEndpoint         string            `mapstructure:"token_endpoint"`
	Scopes                []string          `mapstructure:"scopes"`
	ClaimsMapping         map[string]string `mapstructure:"claims_mapping"`
}

type Proxy struct {
	BaseURL    string `mapstructure:"base_url"`
	ListenAddr string `mapstructure:"listen_addr"`
}

type Config struct {
	Proxy      Proxy `mapstructure:"proxy"`
	IDP        IDP   `mapstructure:"idp"`
	Encryption struct {
		MasterKey string `mapstructure:"master_key"`
	} `mapstructure:"encryption"`
	Upstream Upstream `mapstructure:"upstream"`
}

func Load() (*Config, error) {
	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	viper.AutomaticEnv()
	viper.SetEnvPrefix("MCP")
	viper.BindEnv("proxy.base_url", "MCP_PROXY_BASE_URL")
	viper.BindEnv("idp.client_secret", "MCP_IDP_CLIENT_SECRET")

	if err := viper.ReadInConfig(); err != nil {
		return nil, err
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
