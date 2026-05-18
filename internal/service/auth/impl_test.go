package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel"
	"golang.org/x/oauth2"
)

// --- Test helpers ---

func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func rsaPublicKeyToJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Kid: kid,
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func signTestJWT(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	if kid != "" {
		token.Header["kid"] = kid
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func tokenHandler(accessToken, refreshToken string, statusCode int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "server_error"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  accessToken,
			"token_type":    "Bearer",
			"expires_in":    3600,
			"refresh_token": refreshToken,
		})
	}
}

func makeEncryptedClientID(t *testing.T, redirectURIs []string, secret string) string {
	t.Helper()
	data := ClientIdData{RedirectURIs: redirectURIs, Secret: secret}
	dataJSON, err := json.Marshal(data)
	require.NoError(t, err)
	return "encrypted_" + string(dataJSON)
}

func makeEncryptedState(t *testing.T, originalState, redirectURI, clientID string) string {
	t.Helper()
	data := StateData{OriginalState: originalState, RedirectURI: redirectURI, ClientID: clientID}
	dataJSON, err := json.Marshal(data)
	require.NoError(t, err)
	return "encrypted_" + string(dataJSON)
}

// --- TestNew ---

func TestNew(t *testing.T) {
	key := testRSAKey(t)

	t.Run("success", func(t *testing.T) {
		jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(&key.PublicKey, "kid-1")}})
		}))
		defer jwksServer.Close()

		oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/authorize",
				TokenEndpoint:         "https://example.com/token",
				JWKSEndpoint:          jwksServer.URL,
			})
		}))
		defer oidcServer.Close()

		cfg := config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
			IDP: config.IDP{
				ClientID:               "test-client",
				ClientSecret:           "test-secret",
				OpenIDConfigurationURL: oidcServer.URL,
				Scopes:                 []string{"openid"},
			},
		}

		svc, err := New(cfg, &mockEncryption{})
		require.NoError(t, err)
		assert.NotNil(t, svc)
	})

	t.Run("openid config fetch failure", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer server.Close()

		cfg := config.Config{
			IDP: config.IDP{OpenIDConfigurationURL: server.URL},
		}

		svc, err := New(cfg, &mockEncryption{})
		assert.Error(t, err)
		assert.Nil(t, svc)
	})

	t.Run("jwks fetch failure", func(t *testing.T) {
		jwksFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer jwksFail.Close()

		oidcServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(OpenIDConfiguration{
				JWKSEndpoint: jwksFail.URL,
			})
		}))
		defer oidcServer.Close()

		cfg := config.Config{
			IDP: config.IDP{OpenIDConfigurationURL: oidcServer.URL},
		}

		svc, err := New(cfg, &mockEncryption{})
		assert.Error(t, err)
		assert.Nil(t, svc)
	})
}

// --- TestValidateJWT ---

func TestValidateJWT(t *testing.T) {
	key := testRSAKey(t)
	key2 := testRSAKey(t)
	kid := "test-kid-1"

	jwksWithKey := &JWKS{Keys: []JWK{rsaPublicKeyToJWK(&key.PublicKey, kid)}}
	emptyJWKS := &JWKS{Keys: []JWK{}}

	// Server that returns JWKS with the correct key (for refresh-success test)
	refreshOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(&key.PublicKey, kid)}})
	}))
	defer refreshOK.Close()

	// Server that returns 500 (for refresh-failure test)
	refreshFail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer refreshFail.Close()

	// Server that returns JWKS with a different kid (for still-missing test)
	refreshMiss := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JWKS{Keys: []JWK{rsaPublicKeyToJWK(&key.PublicKey, "different-kid")}})
	}))
	defer refreshMiss.Close()

	now := time.Now()
	validClaims := jwt.MapClaims{
		"sub": "user123",
		"exp": float64(now.Add(time.Hour).Unix()),
	}

	tests := []struct {
		name         string
		jwks         *JWKS
		jwksEndpoint string
		token        string
		leeway       time.Duration
		wantErr      bool
		errContains  string
	}{
		{
			name:  "valid token",
			jwks:  jwksWithKey,
			token: signTestJWT(t, key, kid, validClaims),
		},
		{
			name:        "expired token",
			jwks:        jwksWithKey,
			token:       signTestJWT(t, key, kid, jwt.MapClaims{"sub": "user", "exp": float64(now.Add(-time.Hour).Unix())}),
			wantErr:     true,
			errContains: "expired",
		},
		{
			name:   "expired token within leeway",
			jwks:   jwksWithKey,
			token:  signTestJWT(t, key, kid, jwt.MapClaims{"sub": "user", "exp": float64(now.Add(-30 * time.Second).Unix())}),
			leeway: 60 * time.Second,
		},
		{
			name:        "missing kid header",
			jwks:        jwksWithKey,
			token:       signTestJWT(t, key, "", validClaims),
			wantErr:     true,
			errContains: "missing kid",
		},
		{
			name:         "unknown kid triggers JWKS refresh and succeeds",
			jwks:         emptyJWKS,
			jwksEndpoint: refreshOK.URL,
			token:        signTestJWT(t, key, kid, validClaims),
		},
		{
			name:         "unknown kid JWKS refresh fails",
			jwks:         emptyJWKS,
			jwksEndpoint: refreshFail.URL,
			token:        signTestJWT(t, key, kid, validClaims),
			wantErr:      true,
			errContains:  "JWKS refresh failed",
		},
		{
			name:         "unknown kid still missing after refresh",
			jwks:         emptyJWKS,
			jwksEndpoint: refreshMiss.URL,
			token:        signTestJWT(t, key, kid, validClaims),
			wantErr:      true,
			errContains:  "not found after JWKS refresh",
		},
		{
			name:        "wrong signing key",
			jwks:        jwksWithKey,
			token:       signTestJWT(t, key2, kid, validClaims),
			wantErr:     true,
			errContains: "signature is invalid",
		},
		{
			name:    "malformed token string",
			jwks:    jwksWithKey,
			token:   "not.a.jwt",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := &ProxyAuthHandler{
				config: config.Config{IDP: config.IDP{JWTLeeway: tt.leeway}},
				jwks:   tt.jwks,
				openidConfiguration: &OpenIDConfiguration{
					JWKSEndpoint: tt.jwksEndpoint,
				},
				tracer: otel.Tracer("test"),
			}

			token, err := handler.ValidateJWT(context.Background(), tt.token)
			if tt.wantErr {
				assert.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
				return
			}
			require.NoError(t, err)
			assert.True(t, token.Valid)
		})
	}
}

// --- TestRegisterClient ---

func TestRegisterClient(t *testing.T) {
	handler := &ProxyAuthHandler{
		encryption: &mockEncryption{},
		tracer:     otel.Tracer("test"),
	}

	t.Run("success", func(t *testing.T) {
		req := &RegisterRequest{
			ClientName:   "Test Client",
			RedirectURIs: []string{"http://localhost:3000/callback"},
			GrantTypes:   []string{"authorization_code"},
		}

		resp, err := handler.RegisterClient(context.Background(), req)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.ClientID)
		assert.NotEmpty(t, resp.ClientSecret)
		assert.Len(t, resp.ClientSecret, 64) // 32 bytes → 64 hex chars

		// RFC 7591 §3.2.1 server-generated fields
		assert.Greater(t, resp.ClientIDIssuedAt, int64(0))
		assert.Equal(t, int64(0), resp.ClientSecretExpiresAt)

		// Echo-back with defaults
		assert.Equal(t, req.ClientName, resp.ClientName)
		assert.Equal(t, req.RedirectURIs, resp.RedirectURIs)
		assert.Equal(t, []string{"authorization_code"}, resp.GrantTypes)
		assert.Equal(t, []string{"code"}, resp.ResponseTypes)
		assert.Equal(t, "none", resp.TokenEndpointAuthMethod)

		// Verify round-trip: decode client ID and verify contents
		decoded, err := DecodeClientID(resp.ClientID, handler.encryption)
		require.NoError(t, err)
		assert.Equal(t, req.RedirectURIs, decoded.RedirectURIs)
		assert.Equal(t, resp.ClientSecret, decoded.Secret)
	})

	t.Run("multiple redirect URIs", func(t *testing.T) {
		req := &RegisterRequest{
			ClientName:   "Multi-URI Client",
			RedirectURIs: []string{"http://localhost/cb1", "http://localhost/cb2"},
		}

		resp, err := handler.RegisterClient(context.Background(), req)
		require.NoError(t, err)

		decoded, err := DecodeClientID(resp.ClientID, handler.encryption)
		require.NoError(t, err)
		assert.Equal(t, req.RedirectURIs, decoded.RedirectURIs)
	})

	t.Run("encryption failure", func(t *testing.T) {
		failHandler := &ProxyAuthHandler{
			encryption: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", fmt.Errorf("encryption failed")
				},
			},
			tracer: otel.Tracer("test"),
		}

		req := &RegisterRequest{
			RedirectURIs: []string{"http://localhost/callback"},
		}

		_, err := failHandler.RegisterClient(context.Background(), req)
		assert.Error(t, err)
	})
}

// --- TestAuthenticateRequest ---

func TestAuthenticateRequest(t *testing.T) {
	enc := &mockEncryption{}
	handler := &ProxyAuthHandler{
		config: config.Config{
			Proxy: config.Proxy{BaseURL: "http://localhost:8080"},
		},
		oauthConfig: &oauth2.Config{
			ClientID: "test-client",
			Endpoint: oauth2.Endpoint{
				AuthURL: "https://idp.example.com/authorize",
			},
		},
		encryption: enc,
		tracer:     otel.Tracer("test"),
	}

	t.Run("nil request", func(t *testing.T) {
		_, err := handler.AuthenticateRequest(context.Background(), nil)
		assert.Error(t, err)
	})

	t.Run("empty client_id", func(t *testing.T) {
		_, err := handler.AuthenticateRequest(context.Background(), &AuthenticateRequest{})
		assert.Error(t, err)
	})

	t.Run("invalid encrypted client_id", func(t *testing.T) {
		_, err := handler.AuthenticateRequest(context.Background(), &AuthenticateRequest{
			ClientID:    "not-valid-json",
			RedirectURI: "http://localhost/callback",
			State:       "state",
		})
		assert.Error(t, err)
	})

	t.Run("redirect URI not registered", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://localhost/callback"}, "secret")
		_, err := handler.AuthenticateRequest(context.Background(), &AuthenticateRequest{
			ClientID:    encClientID,
			RedirectURI: "http://evil.com/steal",
			State:       "state",
		})
		assert.Error(t, err)
	})

	t.Run("state encryption failure", func(t *testing.T) {
		failHandler := &ProxyAuthHandler{
			config: config.Config{Proxy: config.Proxy{BaseURL: "http://localhost:8080"}},
			oauthConfig: &oauth2.Config{
				Endpoint: oauth2.Endpoint{AuthURL: "https://idp.example.com/authorize"},
			},
			encryption: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", fmt.Errorf("encrypt failed")
				},
			},
			tracer: otel.Tracer("test"),
		}

		encClientID := makeEncryptedClientID(t, []string{"http://localhost/callback"}, "secret")
		_, err := failHandler.AuthenticateRequest(context.Background(), &AuthenticateRequest{
			ClientID:            encClientID,
			RedirectURI:         "http://localhost/callback",
			State:               "state",
			CodeChallenge:       "challenge",
			CodeChallengeMethod: "S256",
		})
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://localhost/callback"}, "secret")
		authURL, err := handler.AuthenticateRequest(context.Background(), &AuthenticateRequest{
			ClientID:            encClientID,
			RedirectURI:         "http://localhost/callback",
			State:               "user-state",
			CodeChallenge:       "test-challenge",
			CodeChallengeMethod: "S256",
		})
		require.NoError(t, err)
		assert.Contains(t, authURL, "https://idp.example.com/authorize")
		assert.Contains(t, authURL, "code_challenge=test-challenge")
		assert.Contains(t, authURL, "code_challenge_method=S256")
	})
}

// --- TestManageAuthorizationCode ---

func TestManageAuthorizationCode(t *testing.T) {
	handler := &ProxyAuthHandler{
		encryption: &mockEncryption{},
		tracer:     otel.Tracer("test"),
	}

	t.Run("nil request", func(t *testing.T) {
		_, _, err := handler.ManageAuthorizationCode(context.Background(), nil)
		assert.Error(t, err)
	})

	t.Run("invalid state", func(t *testing.T) {
		_, _, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
			State: "not-valid-json",
			Code:  "code",
		})
		assert.Error(t, err)
	})

	t.Run("invalid client_id in state", func(t *testing.T) {
		encState := makeEncryptedState(t, "state", "http://localhost/cb", "not-valid-json")
		_, _, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
			State: encState,
			Code:  "code",
		})
		assert.Error(t, err)
	})

	t.Run("redirect URI not in client data", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://registered.com/cb"}, "secret")
		encState := makeEncryptedState(t, "state", "http://different.com/cb", encClientID)
		_, _, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
			State: encState,
			Code:  "code",
		})
		assert.Error(t, err)
	})

	t.Run("invalid redirect URI scheme", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"ftp://example.com/cb"}, "secret")
		encState := makeEncryptedState(t, "state", "ftp://example.com/cb", encClientID)
		_, _, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
			State: encState,
			Code:  "code",
		})
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		encClientID := makeEncryptedClientID(t, []string{"http://localhost:3000/callback"}, "secret")
		encState := makeEncryptedState(t, "original-state-123", "http://localhost:3000/callback", encClientID)

		code, redirectURL, err := handler.ManageAuthorizationCode(context.Background(), &AuthorizationCodeData{
			State: encState,
			Code:  "auth-code-456",
		})
		require.NoError(t, err)
		assert.Equal(t, "original-state-123", code.State)
		assert.Equal(t, "auth-code-456", code.Code)
		assert.Equal(t, "http", redirectURL.Scheme)
		assert.Equal(t, "localhost:3000", redirectURL.Host)
	})
}

// --- TestRetrieveAccessToken ---

func TestRetrieveAccessToken(t *testing.T) {
	t.Run("nil request", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			tracer: otel.Tracer("test"),
		}
		_, err := handler.RetrieveAccessToken(context.Background(), nil)
		assert.Error(t, err)
	})

	t.Run("empty code", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			tracer: otel.Tracer("test"),
		}
		_, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{})
		assert.Error(t, err)
	})

	t.Run("wrong client secret", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{},
			encryption:  &mockEncryption{},
			tracer:      otel.Tracer("test"),
		}

		encClientID := makeEncryptedClientID(t, []string{"http://localhost/cb"}, "correct-secret")
		_, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:         "auth-code",
			ClientID:     encClientID,
			ClientSecret: "wrong-secret",
		})
		assert.Error(t, err)
	})

	t.Run("idp token exchange error", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("", "", http.StatusBadRequest))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{},
			tracer:     otel.Tracer("test"),
		}

		_, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:       "bad-code",
			GrantTypes: "authorization_code",
		})
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("idp-access-jwt", "idp-refresh-token", http.StatusOK))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{},
			tracer:     otel.Tracer("test"),
		}

		encClientID := makeEncryptedClientID(t, []string{"http://localhost/cb"}, "my-secret")
		token, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:         "auth-code",
			ClientID:     encClientID,
			ClientSecret: "my-secret",
			CodeVerifier: "verifier",
			GrantTypes:   "authorization_code",
		})
		require.NoError(t, err)
		assert.Equal(t, "encrypted_idp-access-jwt", token.AccessToken)
		assert.Equal(t, "encrypted_idp-refresh-token", token.RefreshToken)
		assert.Equal(t, "Bearer", token.TokenType)
	})

	t.Run("success without client_id", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("idp-jwt", "idp-refresh", http.StatusOK))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{},
			tracer:     otel.Tracer("test"),
		}

		token, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:       "auth-code",
			GrantTypes: "authorization_code",
		})
		require.NoError(t, err)
		assert.Equal(t, "encrypted_idp-jwt", token.AccessToken)
		assert.Equal(t, "encrypted_idp-refresh", token.RefreshToken)
	})

	t.Run("access token encryption failure", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("idp-jwt", "idp-refresh", http.StatusOK))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", fmt.Errorf("encryption failed")
				},
			},
			tracer: otel.Tracer("test"),
		}

		_, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:       "auth-code",
			GrantTypes: "authorization_code",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "encryption failed")
	})

	t.Run("refresh token encryption failure", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("idp-jwt", "idp-refresh", http.StatusOK))
		defer ts.Close()

		callCount := 0
		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					callCount++
					if callCount == 2 { // fail on refresh token (second call)
						return "", fmt.Errorf("refresh encrypt failed")
					}
					return "encrypted_" + string(data), nil
				},
			},
			tracer: otel.Tracer("test"),
		}

		_, err := handler.RetrieveAccessToken(context.Background(), &AccessTokenRequest{
			Code:       "auth-code",
			GrantTypes: "authorization_code",
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "refresh encrypt failed")
	})
}

// --- TestRefreshToken ---

func TestRefreshToken(t *testing.T) {
	t.Run("empty refresh token", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			tracer: otel.Tracer("test"),
		}
		_, err := handler.RefreshToken(context.Background(), "")
		assert.Error(t, err)
	})

	t.Run("decryption failure", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			encryption: &mockEncryption{
				decryptFunc: func(enc string) ([]byte, error) {
					return nil, fmt.Errorf("decryption failed")
				},
			},
			tracer: otel.Tracer("test"),
		}
		_, err := handler.RefreshToken(context.Background(), "bad-token")
		assert.Error(t, err)
	})

	t.Run("empty after decryption", func(t *testing.T) {
		handler := &ProxyAuthHandler{
			encryption: &mockEncryption{
				decryptFunc: func(enc string) ([]byte, error) {
					return []byte{}, nil
				},
			},
			tracer: otel.Tracer("test"),
		}
		_, err := handler.RefreshToken(context.Background(), "some-token")
		assert.Error(t, err)
	})

	t.Run("idp refresh error", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("", "", http.StatusBadRequest))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{},
			tracer:     otel.Tracer("test"),
		}

		_, err := handler.RefreshToken(context.Background(), "encrypted_real-refresh-token")
		assert.Error(t, err)
	})

	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("new-access-jwt", "new-refresh-token", http.StatusOK))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{},
			tracer:     otel.Tracer("test"),
		}

		token, err := handler.RefreshToken(context.Background(), "encrypted_real-refresh-token")
		require.NoError(t, err)
		assert.Equal(t, "encrypted_new-access-jwt", token.AccessToken)
		assert.Equal(t, "encrypted_new-refresh-token", token.RefreshToken)
	})

	t.Run("encryption failure after refresh", func(t *testing.T) {
		ts := httptest.NewServer(tokenHandler("new-jwt", "new-refresh", http.StatusOK))
		defer ts.Close()

		handler := &ProxyAuthHandler{
			oauthConfig: &oauth2.Config{
				ClientID: "test-client",
				Endpoint: oauth2.Endpoint{
					TokenURL:  ts.URL,
					AuthStyle: oauth2.AuthStyleInParams,
				},
			},
			encryption: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", fmt.Errorf("encryption failed")
				},
			},
			tracer: otel.Tracer("test"),
		}

		_, err := handler.RefreshToken(context.Background(), "encrypted_real-refresh-token")
		assert.Error(t, err)
	})
}
