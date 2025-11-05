// internal/server/metadata.go
package server

import (
	"encoding/json"
	"net/http"

	"mcpproxy/internal/config"
)

// OpenIDConfigurationHandler serves /.well-known/openid-configuration (RFC 8414)
func OpenIDConfigurationHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"issuer":                                cfg.Proxy.BaseURL,
			"authorization_endpoint":                cfg.Proxy.BaseURL + "/auth",
			"token_endpoint":                        cfg.Proxy.BaseURL + "/token",
			"response_types_supported":              []string{"code"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256"},
			"scopes_supported":                      []string{"openid", "mcp"},
			"token_endpoint_auth_methods_supported": []string{"none"},
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(data)
	}
}

// ProtectedResourceMetadataHandler serves /.well-known/oauth-protected-resource (RFC 9728)
func ProtectedResourceMetadataHandler(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		protected := make([]map[string]string, len(cfg.Upstreams))
		for i, u := range cfg.Upstreams {
			protected[i] = map[string]string{
				"resource": u.Resource,
			}
		}

		data := map[string]interface{}{
			"authorization_servers":         []string{cfg.Proxy.BaseURL},
			"resource":                      cfg.Proxy.BaseURL,
			"resource_indicators_supported": true,
			"protected_resources":           protected,
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		json.NewEncoder(w).Encode(data)
	}
}

// WWWAuthenticateHeader returns the 401 header value
func WWWAuthenticateHeader(baseURL string) string {
	return `Bearer resource_metadata="` + baseURL + `/.well-known/oauth-protected-resource"`
}
