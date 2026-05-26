package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"mcpproxy/internal/infrastructure/config"
)

// TestValidateClientAuth exercises all three branches of validateClientAuth:
// CIMD + private_key_jwt, CIMD public client, and opaque encrypted client_id.
func TestValidateClientAuth(t *testing.T) {
	rsaKey := testRSAKey(t)
	kid := "client-key-1"
	clientID := "https://client.example.com/meta.json"
	tokenEndpoint := "http://localhost:8080/token"

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(&rsaKey.PublicKey, kid)}})
	}))
	defer jwksServer.Close()

	handler := &ProxyAuthHandler{
		config: config.Config{Proxy: config.Proxy{BaseURL: "http://localhost:8080"}},
		tracer: otel.Tracer("test"),
		cimdCache: &cimdCache{entries: make(map[string]cimdCacheEntry)},
		cimdFetcher: func(url string, _ *http.Client, _ *cimdCache) (*ClientMetadataDocument, error) {
			return &ClientMetadataDocument{
				ClientID:                url,
				ClientName:              "Test Client",
				RedirectURIs:            []string{"https://client.example.com/cb"},
				TokenEndpointAuthMethod: "private_key_jwt",
				JwksURI:                 jwksServer.URL,
			}, nil
		},
		httpClient: jwksServer.Client(),
		jtiStore:   newJTIStore(),
		encryption: &mockEncryption{},
	}

	t.Run("CIMD with valid private_key_jwt", func(t *testing.T) {
		assertion := makeClientAssertion(t, rsaKey, kid, clientID, tokenEndpoint, "vcauth-pjwt-1", time.Now().Add(5*time.Minute))
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
			ClientAssertion:     assertion,
		})
		require.NoError(t, err)
	})

	t.Run("CIMD without assertion is public client (no secret needed)", func(t *testing.T) {
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID: clientID,
		})
		require.NoError(t, err)
	})

	t.Run("CIMD with non-jwt-bearer assertion type treated as public client", func(t *testing.T) {
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: "urn:ietf:params:oauth:client-assertion-type:saml2-bearer",
			ClientAssertion:     "some-saml-assertion",
		})
		require.NoError(t, err)
	})

	t.Run("opaque encrypted client_id with correct secret", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://localhost/cb"}, "correct-secret")
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID:     encClientID,
			ClientSecret: "correct-secret",
		})
		require.NoError(t, err)
	})

	t.Run("opaque encrypted client_id with wrong secret", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://localhost/cb"}, "correct-secret")
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID:     encClientID,
			ClientSecret: "wrong-secret",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})

	t.Run("client_id with invalid JSON after decryption returns invalid_request", func(t *testing.T) {
		err := handler.validateClientAuth(context.Background(), &AccessTokenRequest{
			ClientID:     "encrypted_not-valid-json{{{",
			ClientSecret: "any",
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_request")
	})
}

// TestJWTAudienceContains verifies the RFC 7519 §4.1.3 dual-format aud parsing.
func TestJWTAudienceContains(t *testing.T) {
	target := "https://proxy.example.com/token"

	tests := []struct {
		name   string
		claims jwt.MapClaims
		want   bool
	}{
		{
			name:   "missing aud claim",
			claims: jwt.MapClaims{"iss": "example"},
			want:   false,
		},
		{
			name:   "nil aud value",
			claims: jwt.MapClaims{"aud": nil},
			want:   false,
		},
		{
			name:   "string aud matches",
			claims: jwt.MapClaims{"aud": target},
			want:   true,
		},
		{
			name:   "string aud no match",
			claims: jwt.MapClaims{"aud": "https://other.example.com/token"},
			want:   false,
		},
		{
			name:   "array aud contains target",
			claims: jwt.MapClaims{"aud": []any{"https://a.com/token", target}},
			want:   true,
		},
		{
			name:   "array aud does not contain target",
			claims: jwt.MapClaims{"aud": []any{"https://a.com/token", "https://b.com/token"}},
			want:   false,
		},
		{
			name:   "array aud with non-string entries alongside target",
			claims: jwt.MapClaims{"aud": []any{42, nil, target}},
			want:   true,
		},
		{
			name:   "empty array aud",
			claims: jwt.MapClaims{"aud": []any{}},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := jwtAudienceContains(tt.claims, target)
			assert.Equal(t, tt.want, got)
		})
	}
}
