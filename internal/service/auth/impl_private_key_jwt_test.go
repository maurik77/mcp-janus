package auth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
)

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func makeClientAssertion(t *testing.T, key *rsa.PrivateKey, kid, clientID, tokenEndpoint, jti string, exp time.Time) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss": clientID,
		"sub": clientID,
		"aud": tokenEndpoint,
		"jti": jti,
		"exp": exp.Unix(),
		"iat": time.Now().Unix(),
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	signed, err := tok.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestValidatePrivateKeyJWT(t *testing.T) {
	rsaKey := testRSAKey(t)
	kid := "client-key-1"
	tokenEndpoint := "http://localhost:8080/token"
	clientID := "https://client.example.com/meta.json"

	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(&rsaKey.PublicKey, kid)}})
	}))
	defer jwksServer.Close()

	cimdServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		doc := ClientMetadataDocument{
			ClientID:                clientID,
			ClientName:              "Test Client",
			RedirectURIs:            []string{"https://client.example.com/cb"},
			TokenEndpointAuthMethod: "private_key_jwt",
			JwksURI:                 jwksServer.URL,
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
	defer cimdServer.Close()

	handler := &ProxyAuthHandler{
		config: config.Config{Proxy: config.Proxy{BaseURL: "http://localhost:8080"}},
		tracer:    otel.Tracer("test"),
		cimdCache: &cimdCache{entries: make(map[string]cimdCacheEntry)},
		cimdFetcher: func(url string, _ *http.Client, _ *cimdCache) (*ClientMetadataDocument, error) {
			return &ClientMetadataDocument{
				ClientID:                clientID,
				ClientName:              "Test Client",
				RedirectURIs:            []string{"https://client.example.com/cb"},
				TokenEndpointAuthMethod: "private_key_jwt",
				JwksURI:                 jwksServer.URL,
			}, nil
		},
		httpClient: jwksServer.Client(),
		jtiStore:   newJTIStore(),
	}

	t.Run("valid assertion", func(t *testing.T) {
		assertion := makeClientAssertion(t, rsaKey, kid, clientID, tokenEndpoint, "jti-valid-1", time.Now().Add(5*time.Minute))
		err := handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.NoError(t, err)
	})

	t.Run("replayed jti is rejected", func(t *testing.T) {
		assertion := makeClientAssertion(t, rsaKey, kid, clientID, tokenEndpoint, "jti-replay", time.Now().Add(5*time.Minute))
		err := handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.NoError(t, err) // first use OK

		err = handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})

	t.Run("expired assertion rejected", func(t *testing.T) {
		assertion := makeClientAssertion(t, rsaKey, kid, clientID, tokenEndpoint, "jti-expired", time.Now().Add(-time.Minute))
		err := handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.Error(t, err)
	})

	t.Run("wrong audience rejected", func(t *testing.T) {
		assertion := makeClientAssertion(t, rsaKey, kid, clientID, "https://wrong.example.com/token", "jti-aud", time.Now().Add(5*time.Minute))
		err := handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})

	t.Run("iss/sub mismatch rejected", func(t *testing.T) {
		// Build a JWT where iss != clientID
		claims := jwt.MapClaims{
			"iss": "https://attacker.example.com/meta.json",
			"sub": clientID,
			"aud": tokenEndpoint,
			"jti": "jti-iss-mismatch",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}
		tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		tok.Header["kid"] = kid
		assertion, err := tok.SignedString(rsaKey)
		require.NoError(t, err)

		err = handler.validatePrivateKeyJWT(context.Background(), &AccessTokenRequest{
			ClientID:            clientID,
			ClientAssertionType: clientAssertionType,
			ClientAssertion:     assertion,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid_client")
	})
}

// TestManageAuthorizationCode_ISSInRedirect verifies that the iss param is appended.
func TestManageAuthorizationCode_ISSInRedirect(t *testing.T) {
	handler := &ProxyAuthHandler{
		config: config.Config{
			Proxy: config.Proxy{
				BaseURL: "http://localhost:8080",
				Issuer:  "https://proxy.example.com",
			},
		},
		encryption: &mockEncryption{},
		tracer:     otel.Tracer("test"),
	}

	encClientID := makeEncryptedClientID(t, []string{"http://localhost:3000/callback"}, "secret")
	encState := makeEncryptedState(t, "state-xyz", "http://localhost:3000/callback", encClientID)

	_, redirectURL, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
		State: encState,
		Code:  "code-123",
	})
	require.NoError(t, err)
	assert.Equal(t, "https://proxy.example.com", redirectURL.Query().Get("iss"))
}

// TestManageAuthorizationCode_ISSFallback verifies issuer falls back to BaseURL.
func TestManageAuthorizationCode_ISSFallback(t *testing.T) {
	handler := &ProxyAuthHandler{
		config: config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"}, // no Issuer set
		},
		encryption: &mockEncryption{},
		tracer:     otel.Tracer("test"),
	}

	encClientID := makeEncryptedClientID(t, []string{"http://localhost:3000/callback"}, "secret")
	encState := makeEncryptedState(t, "state-xyz", "http://localhost:3000/callback", encClientID)

	_, redirectURL, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
		State: encState,
		Code:  "code-123",
	})
	require.NoError(t, err)
	assert.Equal(t, "http://localhost:8080", redirectURL.Query().Get("iss"))
}
