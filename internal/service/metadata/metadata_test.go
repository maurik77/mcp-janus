package metadata

import (
	"mcpproxy/internal/infrastructure/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_IssuerResolution(t *testing.T) {
	t.Run("uses Issuer when set", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{
				BaseURL: "http://localhost:8080",
				Issuer:  "https://proxy.example.com",
			},
		})
		require.NoError(t, err)
		meta := svc.OpenIDConfiguration().(map[string]any)
		assert.Equal(t, "https://proxy.example.com", meta["issuer"])
	})

	t.Run("falls back to BaseURL when Issuer is empty", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
		})
		require.NoError(t, err)
		meta := svc.OpenIDConfiguration().(map[string]any)
		assert.Equal(t, "http://localhost:8080", meta["issuer"])
	})
}

func TestOpenIDConfiguration(t *testing.T) {
	svc, err := New(config.Config{
		Proxy: config.Proxy{
			BaseURL: "http://localhost:8080",
			Issuer:  "https://proxy.example.com",
		},
	})
	require.NoError(t, err)

	raw := svc.OpenIDConfiguration()
	meta, ok := raw.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "https://proxy.example.com", meta["issuer"])
	assert.Equal(t, "http://localhost:8080/auth", meta["authorization_endpoint"])
	assert.Equal(t, "http://localhost:8080/token", meta["token_endpoint"])
	assert.Equal(t, "http://localhost:8080/register", meta["registration_endpoint"])
	assert.Equal(t, []string{"code"}, meta["response_types_supported"])
	assert.Equal(t, []string{"S256"}, meta["code_challenge_methods_supported"])
	assert.Equal(t, []string{"none", "private_key_jwt"}, meta["token_endpoint_auth_methods_supported"])
	assert.Equal(t, []string{"RS256"}, meta["token_endpoint_auth_signing_alg_values_supported"])
	assert.Equal(t, true, meta["client_id_metadata_document_supported"])
	assert.Equal(t, true, meta["authorization_response_iss_parameter_supported"])
}

func TestAuthorizationServerMetadata(t *testing.T) {
	svc, err := New(config.Config{
		Proxy: config.Proxy{
			BaseURL: "http://localhost:8080",
			Issuer:  "https://proxy.example.com",
		},
	})
	require.NoError(t, err)

	raw := svc.AuthorizationServerMetadata()
	meta, ok := raw.(map[string]any)
	require.True(t, ok)

	assert.Equal(t, "https://proxy.example.com", meta["issuer"])
	assert.Equal(t, "http://localhost:8080/auth", meta["authorization_endpoint"])
	assert.Equal(t, "http://localhost:8080/token", meta["token_endpoint"])
	assert.Equal(t, "http://localhost:8080/register", meta["registration_endpoint"])
	assert.Equal(t, []string{"none", "private_key_jwt"}, meta["token_endpoint_auth_methods_supported"])
	assert.Equal(t, []string{"RS256"}, meta["token_endpoint_auth_signing_alg_values_supported"])
	assert.Equal(t, true, meta["client_id_metadata_document_supported"])
	assert.Equal(t, true, meta["authorization_response_iss_parameter_supported"])
	// AuthorizationServerMetadata advertises "mcp" scope, not "openid"
	assert.Equal(t, []string{"mcp"}, meta["scopes_supported"])
}

func TestProtectedResourceMetadata(t *testing.T) {
	t.Run("resource is BaseURL", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{
				BaseURL: "https://mcp.example.com",
				Issuer:  "https://proxy.example.com",
			},
		})
		require.NoError(t, err)

		raw := svc.ProtectedResourceMetadata()
		meta, ok := raw.(map[string]any)
		require.True(t, ok)

		assert.Equal(t, "https://mcp.example.com", meta["resource"])
		assert.Equal(t, []string{"https://proxy.example.com"}, meta["authorization_servers"])
	})

	t.Run("authorization_servers uses Issuer", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{
				BaseURL: "http://localhost:8080",
				Issuer:  "https://proxy.example.com",
			},
		})
		require.NoError(t, err)

		raw := svc.ProtectedResourceMetadata()
		meta := raw.(map[string]any)
		assert.Equal(t, []string{"https://proxy.example.com"}, meta["authorization_servers"])
	})

	t.Run("authorization_servers falls back to BaseURL when Issuer empty", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
		})
		require.NoError(t, err)

		raw := svc.ProtectedResourceMetadata()
		meta := raw.(map[string]any)
		assert.Equal(t, []string{"http://localhost:8080"}, meta["authorization_servers"])
	})
}

func TestWWWAuthenticateHeader(t *testing.T) {
	t.Run("no scopes omits scope param", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
		})
		require.NoError(t, err)

		header := svc.WWWAuthenticateHeader()
		assert.Contains(t, header, `Bearer realm="mcp"`)
		assert.Contains(t, header, `resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`)
		assert.NotContains(t, header, "scope=")
	})

	t.Run("single scope included", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
			IDP:   config.IDP{Scopes: []string{"openid"}},
		})
		require.NoError(t, err)

		assert.Contains(t, svc.WWWAuthenticateHeader(), `scope="openid"`)
	})

	t.Run("multiple scopes joined with space", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
			IDP:   config.IDP{Scopes: []string{"openid", "profile", "email"}},
		})
		require.NoError(t, err)

		assert.Contains(t, svc.WWWAuthenticateHeader(), `scope="openid profile email"`)
	})

	t.Run("resource_metadata always uses BaseURL not Issuer", func(t *testing.T) {
		svc, err := New(config.Config{
			Proxy: config.Proxy{
				BaseURL: "http://localhost:8080",
				Issuer:  "https://proxy.example.com",
			},
		})
		require.NoError(t, err)

		header := svc.WWWAuthenticateHeader()
		assert.Contains(t, header, `resource_metadata="http://localhost:8080/.well-known/oauth-protected-resource"`)
		assert.NotContains(t, header, "proxy.example.com")
	})
}
