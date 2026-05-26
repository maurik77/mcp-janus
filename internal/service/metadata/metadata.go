package metadata

import (
	"mcpproxy/internal/infrastructure/config"
	"strings"
)

type MetadataHandler struct {
	config config.Config
	issuer string
}

func New(cfg config.Config) (Service, error) {
	issuer := cfg.Proxy.Issuer
	if issuer == "" {
		issuer = cfg.Proxy.BaseURL
	}

	return &MetadataHandler{
		config: cfg,
		issuer: issuer,
	}, nil
}

// OpenIDConfiguration serves /.well-known/openid-configuration
func (h *MetadataHandler) OpenIDConfiguration() any {
	return map[string]any{
		"issuer":                 h.issuer,
		"authorization_endpoint": h.config.Proxy.BaseURL + "/auth",
		"token_endpoint":         h.config.Proxy.BaseURL + "/token",
		"registration_endpoint":  h.config.Proxy.BaseURL + "/register",
		"response_types_supported":                          []string{"code"},
		"grant_types_supported":                             []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":                  []string{"S256"},
		"scopes_supported":                                  []string{"openid", "mcp"},
		"token_endpoint_auth_methods_supported":             []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported":  []string{"RS256"},
		"client_id_metadata_document_supported":             true,
		"authorization_response_iss_parameter_supported":    true,
	}
}

// AuthorizationServerMetadata serves /.well-known/oauth-authorization-server (RFC 8414)
func (h *MetadataHandler) AuthorizationServerMetadata() any {
	return map[string]any{
		"issuer":                 h.issuer,
		"authorization_endpoint": h.config.Proxy.BaseURL + "/auth",
		"token_endpoint":         h.config.Proxy.BaseURL + "/token",
		"registration_endpoint":  h.config.Proxy.BaseURL + "/register",
		"response_types_supported":                          []string{"code"},
		"grant_types_supported":                             []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":                  []string{"S256"},
		"scopes_supported":                                  []string{"mcp"},
		"token_endpoint_auth_methods_supported":             []string{"none", "private_key_jwt"},
		"token_endpoint_auth_signing_alg_values_supported":  []string{"RS256"},
		"client_id_metadata_document_supported":             true,
		"authorization_response_iss_parameter_supported":    true,
	}
}

// ProtectedResourceMetadata serves /.well-known/oauth-protected-resource (RFC 9728)
func (h *MetadataHandler) ProtectedResourceMetadata() any {
	return map[string]any{
		"authorization_servers":    []string{h.issuer},
		"resource":                 h.config.Proxy.BaseURL + "/mcp",
		"bearer_methods_supported": []string{"header"},
	}
}

// WWWAuthenticateHeader returns the 401 header value
func (h *MetadataHandler) WWWAuthenticateHeader() string {
	header := `Bearer realm="mcp", resource_metadata="` + h.config.Proxy.BaseURL + `/.well-known/oauth-protected-resource"`
	if len(h.config.IDP.Scopes) > 0 {
		header += `, scope="` + strings.Join(h.config.IDP.Scopes, " ") + `"`
	}
	return header
}
