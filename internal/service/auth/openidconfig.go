package auth

import (
	"crypto/tls"
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

func fetchOpenIDConfiguration(url string, skipTLSVerify bool) (*OpenIDConfiguration, error) {
	client := &http.Client{}
	if skipTLSVerify {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		}
	}

	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to fetch OpenID configuration: HTTP %d from %s", resp.StatusCode, url)
	}

	var config OpenIDConfiguration
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, fmt.Errorf("failed to decode OpenID configuration: %w", err)
	}
	return &config, nil
}
