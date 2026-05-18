package wire

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/infrastructure/telemetry"
	"mcpproxy/internal/server"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/metric/noop"
)

// --- Integration test helpers ---

// testRSAKeyInt generates a 2048-bit RSA key for integration tests.
func testRSAKeyInt(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// jwkJSON returns a JWKS JSON response body with the given RSA public key.
func jwkJSON(t *testing.T, pub *rsa.PublicKey, kid string) []byte {
	t.Helper()
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	jwks := map[string]any{
		"keys": []map[string]string{
			{"kty": "RSA", "alg": "RS256", "kid": kid, "n": n, "e": e, "use": "sig"},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return data
}

// signJWTInt creates a signed JWT string with the given claims and kid.
func signJWTInt(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func testMetrics() *telemetry.Metrics {
	meter := noop.NewMeterProvider().Meter("test")
	m, _ := telemetry.InitializeMetrics(meter)
	return m
}

// --- Integration tests ---

// TestIntegration_HealthEndpoint wires the full Gin engine with real services
// and verifies the /health endpoint.
func TestIntegration_HealthEndpoint(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-1"

	// Mock IdP: serves OpenID config, JWKS, and token endpoint
	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idpServer.URL,
			"authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint":         idpServer.URL + "/token",
			"jwks_uri":               idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})

	// Mock upstream MCP server
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL:    "http://localhost:8080",
			ListenAddr: ":8080",
			LogLevel:   "error",
			LogFormat:  "json",
		},
		IDP: config.IDP{
			ClientID:               "test-client",
			ClientSecret:           "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"},
			ClaimsMapping:          map[string]string{"sub": "X-Sub"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{
			MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Upstream: config.Upstream{
			Name:       "test-upstream",
			Resource:   upstream.URL,
			BaseURL:    upstream.URL,
			PathPrefix: "",
		},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)

	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)

	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)

	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)

	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	// Health check
	req := httptest.NewRequest("GET", "/health", nil)
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "OK", rec.Body.String())
}

// TestIntegration_DiscoveryEndpoints verifies the .well-known endpoints.
func TestIntegration_DiscoveryEndpoints(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-2"

	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idpServer.URL,
			"authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint":         idpServer.URL + "/token",
			"jwks_uri":               idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL:    "http://localhost:8080",
			ListenAddr: ":8080",
		},
		IDP: config.IDP{
			ClientID:               "test-client",
			ClientSecret:           "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"},
			ClaimsMapping:          map[string]string{"sub": "X-Sub"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{
			MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
		Upstream: config.Upstream{
			Name:     "test-upstream",
			Resource: "https://mcp.example.com",
			BaseURL:  upstream.URL,
		},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)
	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)
	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)
	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)
	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	t.Run("openid-configuration", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/openid-configuration", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "http://localhost:8080", body["issuer"])
		assert.Equal(t, "http://localhost:8080/auth", body["authorization_endpoint"])
		assert.Equal(t, "http://localhost:8080/token", body["token_endpoint"])
		assert.Equal(t, "http://localhost:8080/register", body["registration_endpoint"])
	})

	t.Run("oauth-protected-resource", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)

		var body map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
		assert.Equal(t, "http://localhost:8080/mcp", body["resource"])
		assert.Equal(t, []any{"header"}, body["bearer_methods_supported"])
	})
}

// TestIntegration_RegisterAndAuth tests the register → auth redirect flow.
func TestIntegration_RegisterAndAuth(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-3"

	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 idpServer.URL,
			"authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint":         idpServer.URL + "/token",
			"jwks_uri":               idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{BaseURL: "http://localhost:8080", ListenAddr: ":8080"},
		IDP: config.IDP{
			ClientID:               "test-client",
			ClientSecret:           "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"},
			ClaimsMapping:          map[string]string{"sub": "X-Sub"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Upstream: config.Upstream{Name: "test", Resource: upstream.URL, BaseURL: upstream.URL},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)
	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)
	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)
	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)
	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	// Step 1: Register client
	regBody := `{"client_name":"test","redirect_uris":["http://localhost:3000/callback"],"grant_types":["authorization_code"],"response_types":["code"]}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	require.Equal(t, http.StatusCreated, rec.Code)

	var regResp auth.RegisterResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &regResp))
	assert.NotEmpty(t, regResp.ClientID)
	assert.NotEmpty(t, regResp.ClientSecret)

	// Step 2: Auth redirect — should redirect to IdP
	authURL := fmt.Sprintf("/auth?client_id=%s&redirect_uri=%s&state=mystate&code_challenge=testchallenge&code_challenge_method=S256",
		url.QueryEscape(regResp.ClientID),
		url.QueryEscape("http://localhost:3000/callback"))
	req = httptest.NewRequest("GET", authURL, nil)
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusFound, rec.Code)
	location := rec.Header().Get("Location")
	assert.Contains(t, location, idpServer.URL+"/authorize")
	assert.Contains(t, location, "code_challenge=testchallenge")
}

// TestIntegration_ProxyUnauthorized tests that /mcp/* returns 401 without a token.
func TestIntegration_ProxyUnauthorized(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-4"

	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": idpServer.URL, "authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint": idpServer.URL + "/token", "jwks_uri": idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called without auth")
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{BaseURL: "http://localhost:8080", ListenAddr: ":8080"},
		IDP: config.IDP{
			ClientID: "test-client", ClientSecret: "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"}, ClaimsMapping: map[string]string{"sub": "X-Sub"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Upstream: config.Upstream{Name: "test", Resource: upstream.URL, BaseURL: upstream.URL},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)
	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)
	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)
	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)
	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	t.Run("no token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mcp/test", nil)
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})

	t.Run("invalid opaque token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/mcp/test", nil)
		req.Header.Set("Authorization", "Bearer not-a-real-token")
		rec := httptest.NewRecorder()
		engine.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
	})
}

// TestIntegration_ProxyWithValidToken tests the full auth middleware → proxy flow
// using a real encrypted JWT that passes validation.
func TestIntegration_ProxyWithValidToken(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-5"

	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": idpServer.URL, "authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint": idpServer.URL + "/token", "jwks_uri": idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})

	// Mock upstream: captures the request to verify headers
	var capturedAuth string
	var capturedSubHeader string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedSubHeader = r.Header.Get("X-Sub")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"proxied":true}`))
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{BaseURL: "http://localhost:8080", ListenAddr: ":8080"},
		IDP: config.IDP{
			ClientID: "test-client", ClientSecret: "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"}, ClaimsMapping: map[string]string{"sub": "X-Sub", "email": "X-Email"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Upstream: config.Upstream{Name: "test", Resource: upstream.URL, BaseURL: upstream.URL},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)
	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)
	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)
	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)
	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	// Create a valid JWT signed with our test RSA key
	realJWT := signJWTInt(t, rsaKey, kid, jwt.MapClaims{
		"sub":   "user-42",
		"email": "user@example.com",
		"iat":   time.Now().Unix(),
		"exp":   time.Now().Add(time.Hour).Unix(),
	})

	// Encrypt the JWT into an opaque token (simulating what /token would return)
	opaqueToken, err := enc.Encrypt([]byte(realJWT))
	require.NoError(t, err)

	// Make an authenticated request to /mcp/test
	req := httptest.NewRequest("POST", "/mcp/test", strings.NewReader(`{"method":"tools/list"}`))
	req.Header.Set("Authorization", "Bearer "+opaqueToken)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)

	// Upstream should have received the real JWT (the opaque token, since
	// the middleware stores the opaque token in context and ProxyHandler
	// uses it as the real token to forward)
	assert.True(t, strings.HasPrefix(capturedAuth, "Bearer "))
	assert.Equal(t, "user-42", capturedSubHeader)
}

// TestIntegration_TokenExchangeFlow tests register → auth → callback → token
// by simulating the IdP token endpoint response.
func TestIntegration_TokenExchangeFlow(t *testing.T) {
	rsaKey := testRSAKeyInt(t)
	kid := "int-kid-6"

	idpMux := http.NewServeMux()
	idpServer := httptest.NewServer(idpMux)
	defer idpServer.Close()

	realJWT := signJWTInt(t, rsaKey, kid, jwt.MapClaims{
		"sub": "user-99",
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Hour).Unix(),
	})

	idpMux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer": idpServer.URL, "authorization_endpoint": idpServer.URL + "/authorize",
			"token_endpoint": idpServer.URL + "/token", "jwks_uri": idpServer.URL + "/jwks",
		})
	})
	idpMux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwkJSON(t, &rsaKey.PublicKey, kid))
	})
	idpMux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		// Simulate IdP token response
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":  realJWT,
			"refresh_token": "idp-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	})

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := config.Config{
		Proxy: config.Proxy{BaseURL: "http://localhost:8080", ListenAddr: ":8080"},
		IDP: config.IDP{
			ClientID: "test-client", ClientSecret: "test-secret",
			OpenIDConfigurationURL: idpServer.URL + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid"}, ClaimsMapping: map[string]string{"sub": "X-Sub"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"},
		Upstream: config.Upstream{Name: "test", Resource: upstream.URL, BaseURL: upstream.URL},
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)
	authSvc, err := auth.New(cfg, enc)
	require.NoError(t, err)
	metaSvc, err := metadata.New(cfg)
	require.NoError(t, err)
	prx, err := server.NewProxy(cfg, metaSvc, authSvc, enc)
	require.NoError(t, err)
	engine, err := NewGinEngine(&cfg, authSvc, metaSvc, prx, enc, testMetrics())
	require.NoError(t, err)

	// Step 1: Register
	regBody := `{"client_name":"test","redirect_uris":["http://localhost:3000/callback"],"grant_types":["authorization_code"],"response_types":["code"]}`
	req := httptest.NewRequest("POST", "/register", strings.NewReader(regBody))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var regResp auth.RegisterResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &regResp))

	// Step 2: Auth redirect
	authURL := fmt.Sprintf("/auth?client_id=%s&redirect_uri=%s&state=mystate&code_challenge=testchallenge&code_challenge_method=S256",
		url.QueryEscape(regResp.ClientID),
		url.QueryEscape("http://localhost:3000/callback"))
	req = httptest.NewRequest("GET", authURL, nil)
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	// Extract encrypted state from the IdP redirect URL
	location, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	encryptedState := location.Query().Get("state")
	require.NotEmpty(t, encryptedState)

	// Step 3: Callback — simulate IdP calling back with code + state
	callbackURL := fmt.Sprintf("/callback?code=idp-auth-code&state=%s", url.QueryEscape(encryptedState))
	req = httptest.NewRequest("GET", callbackURL, nil)
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	require.Equal(t, http.StatusFound, rec.Code)

	// The callback should redirect to the client's redirect_uri with code and original state
	clientRedirect, err := url.Parse(rec.Header().Get("Location"))
	require.NoError(t, err)
	assert.Equal(t, "localhost:3000", clientRedirect.Host)
	assert.Equal(t, "/callback", clientRedirect.Path)
	assert.Equal(t, "mystate", clientRedirect.Query().Get("state"))
	assert.Equal(t, "idp-auth-code", clientRedirect.Query().Get("code"))

	// Step 4: Token exchange
	tokenBody := fmt.Sprintf("code=idp-auth-code&grant_type=authorization_code&code_verifier=testverifier&client_id=%s&client_secret=%s",
		url.QueryEscape(regResp.ClientID),
		url.QueryEscape(regResp.ClientSecret))
	req = httptest.NewRequest("POST", "/token", strings.NewReader(tokenBody))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var tokenResp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokenResp))
	opaqueAccessToken, ok := tokenResp["access_token"].(string)
	require.True(t, ok)
	assert.NotEmpty(t, opaqueAccessToken)

	// The opaque token should NOT be the real JWT
	assert.NotEqual(t, realJWT, opaqueAccessToken)

	// Verify we can decrypt the opaque token back to the real JWT
	decrypted, err := enc.Decrypt(opaqueAccessToken)
	require.NoError(t, err)
	assert.Equal(t, realJWT, string(decrypted))
}
