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

// OpenIDConfigurationHandler serves /.well-known/openid-configuration (RFC 8414)
func (h *MetadataHandler) OpenIDConfiguration() any {
	data := map[string]any{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.config.Proxy.BaseURL + "/auth",
		"token_endpoint":                        h.config.Proxy.BaseURL + "/token",
		"registration_endpoint":                 h.config.Proxy.BaseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"openid", "mcp"},
		"token_endpoint_auth_methods_supported":  []string{"none"},
		"client_id_metadata_document_supported":  true,
	}

	return data
}

// AuthorizationServerMetadata serves /.well-known/oauth-authorization-server (RFC 8414)
func (h *MetadataHandler) AuthorizationServerMetadata() any {
	return map[string]any{
		"issuer":                                h.issuer,
		"authorization_endpoint":                h.config.Proxy.BaseURL + "/auth",
		"token_endpoint":                        h.config.Proxy.BaseURL + "/token",
		"registration_endpoint":                 h.config.Proxy.BaseURL + "/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"scopes_supported":                      []string{"mcp"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"client_id_metadata_document_supported": true,
	}
}

// ProtectedResourceMetadataHandler serves /.well-known/oauth-protected-resource (RFC 9728)
func (h *MetadataHandler) ProtectedResourceMetadata() any {
	data := map[string]any{
		"authorization_servers": []string{h.issuer},
		"resource":              h.config.Proxy.BaseURL,
	}

	return data
}

// WWWAuthenticateHeader returns the 401 header value
func (h *MetadataHandler) WWWAuthenticateHeader() string {
	header := `Bearer realm="mcp", resource_metadata="` + h.config.Proxy.BaseURL + `/.well-known/oauth-protected-resource"`
	if len(h.config.IDP.Scopes) > 0 {
		header += `, scope="` + strings.Join(h.config.IDP.Scopes, " ") + `"`
	}
	return header
}
