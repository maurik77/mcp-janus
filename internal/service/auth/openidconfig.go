package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type OpenIDConfiguration struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSEndpoint          string `json:"jwks_uri"`
}

func fetchOpenIDConfiguration(url string) (*OpenIDConfiguration, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close()

	var config OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OpenID configuration: %w", err)
	}
	return &config, nil
}
