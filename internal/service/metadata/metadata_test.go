package metadata

import (
	"mcpproxy/internal/infrastructure/config"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_IssuerDefaultsToBaseURL(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
			Issuer:  "",
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)
	h := svc.(*MetadataHandler)
	assert.Equal(t, "https://proxy.example.com", h.issuer)
}

func TestNew_IssuerExplicitlySet(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
			Issuer:  "https://custom-issuer.example.com",
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)
	h := svc.(*MetadataHandler)
	assert.Equal(t, "https://custom-issuer.example.com", h.issuer)
}

func TestOpenIDConfiguration_RequiredFields(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
			Issuer:  "https://issuer.example.com",
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)

	result := svc.OpenIDConfiguration().(map[string]any)

	assert.Equal(t, "https://issuer.example.com", result["issuer"])
	assert.Equal(t, "https://proxy.example.com/auth", result["authorization_endpoint"])
	assert.Equal(t, "https://proxy.example.com/token", result["token_endpoint"])
	assert.Equal(t, "https://proxy.example.com/register", result["registration_endpoint"])
	assert.Equal(t, []string{"code"}, result["response_types_supported"])
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, result["grant_types_supported"])
	assert.Equal(t, []string{"S256"}, result["code_challenge_methods_supported"])
	assert.Equal(t, []string{"none", "private_key_jwt"}, result["token_endpoint_auth_methods_supported"])
}

func TestAuthorizationServerMetadata_RequiredFields(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
			Issuer:  "https://issuer.example.com",
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)

	result := svc.AuthorizationServerMetadata().(map[string]any)

	assert.Equal(t, "https://issuer.example.com", result["issuer"])
	assert.Equal(t, "https://proxy.example.com/auth", result["authorization_endpoint"])
	assert.Equal(t, "https://proxy.example.com/token", result["token_endpoint"])
	assert.Equal(t, "https://proxy.example.com/register", result["registration_endpoint"])
	assert.Equal(t, []string{"code"}, result["response_types_supported"])
	assert.Equal(t, []string{"authorization_code", "refresh_token"}, result["grant_types_supported"])
	assert.Equal(t, []string{"S256"}, result["code_challenge_methods_supported"])
	assert.Equal(t, []string{"none", "private_key_jwt"}, result["token_endpoint_auth_methods_supported"])
}

func TestProtectedResourceMetadata_Fields(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
			Issuer:  "https://issuer.example.com",
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)

	result := svc.ProtectedResourceMetadata().(map[string]any)

	assert.Equal(t, []string{"https://issuer.example.com"}, result["authorization_servers"])
	assert.Equal(t, "https://proxy.example.com/mcp", result["resource"])
	assert.Equal(t, []string{"header"}, result["bearer_methods_supported"])
}

func TestWWWAuthenticateHeader_WithScopes(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
		},
		IDP: config.IDP{
			Scopes: []string{"openid", "mcp"},
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)

	header := svc.WWWAuthenticateHeader()

	assert.Contains(t, header, `Bearer realm="mcp"`)
	assert.Contains(t, header, `resource_metadata="https://proxy.example.com/.well-known/oauth-protected-resource"`)
	assert.Contains(t, header, `scope="openid mcp"`)
}

func TestWWWAuthenticateHeader_NoScopes(t *testing.T) {
	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL: "https://proxy.example.com",
		},
		IDP: config.IDP{
			Scopes: nil,
		},
	}
	svc, err := New(cfg)
	require.NoError(t, err)

	header := svc.WWWAuthenticateHeader()

	assert.Contains(t, header, `Bearer realm="mcp"`)
	assert.False(t, strings.Contains(header, "scope="), "scope param should be absent when no scopes configured")
}
