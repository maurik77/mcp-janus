//go:build integration

package auth

// Keycloak end-to-end integration tests.
//
// These tests spin up a real Keycloak 26 container via dockertest and exercise:
//   - Dynamic Client Registration (delegate mode)
//   - JWT validation with issuer and audience claims
//   - RefreshToken using real Keycloak-issued refresh tokens
//
// Run with:
//
//	go test ./internal/service/auth/... -tags integration -timeout 300s -run TestKeycloak
//
// Prerequisites: Docker daemon must be running.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/utility"
)

// ─── Keycloak test constants ──────────────────────────────────────────────────

const (
	kcAdmin        = "admin"
	kcAdminPass    = "admin"
	kcRealm        = "mcp-test"
	kcProxyClient  = "mcp-proxy"
	kcProxySecret  = "proxy-secret-E2E"
	kcTestUser     = "e2euser"
	kcTestUserPass = "E2ePass1!"
	kcAudience     = "http://mcp-upstream-e2e"
	kcEncKey       = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"
)

// ─── Package-level state shared by all Keycloak E2E tests ────────────────────

var (
	kcBaseURL      string // e.g. "http://127.0.0.1:32768"
	kcInitialToken string // DCR initial access token
	kcPool         *dockertest.Pool
	kcResource     *dockertest.Resource
)

// TestMain starts a single Keycloak container for the whole package test run,
// sets up the test realm, then tears down.
// Existing unit tests (no build tag) are unaffected; with -tags integration
// this TestMain is active and the unit tests still pass (they don't use the
// Keycloak globals).
func TestMain(m *testing.M) {
	var err error
	kcPool, err = dockertest.NewPool("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dockertest.NewPool: %v\n", err)
		os.Exit(1)
	}
	if err = kcPool.Client.Ping(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot reach Docker: %v\n", err)
		os.Exit(1)
	}

	kcResource, kcBaseURL = mustStartKeycloak(kcPool)

	adminToken := mustAdminToken(kcBaseURL)
	kcInitialToken = mustSetupRealm(kcBaseURL, adminToken)

	code := m.Run()

	if err := kcPool.Purge(kcResource); err != nil {
		fmt.Fprintf(os.Stderr, "purge Keycloak: %v\n", err)
	}
	os.Exit(code)
}

// ─── Tests ───────────────────────────────────────────────────────────────────

// TestKeycloak_DCR_DelegateRegistration verifies that, in delegate mode, the
// proxy calls Keycloak's DCR endpoint and stores the resulting credentials
// inside the encrypted client_id blob.
func TestKeycloak_DCR_DelegateRegistration(t *testing.T) {
	enc, svc := buildService(t, func(idp *config.IDP) {
		idp.RegistrationMode = "delegate"
		idp.RegistrationInitialToken = kcInitialToken
	})

	resp, err := svc.RegisterClient(context.Background(), &RegisterRequest{
		ClientName:              "e2e-test-client",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	})
	require.NoError(t, err, "RegisterClient in delegate mode")
	require.NotEmpty(t, resp.ClientID)
	require.NotEmpty(t, resp.ClientSecret)

	// Decode the opaque client_id blob and verify Keycloak creds are embedded.
	decoded, err := DecodeClientID(resp.ClientID, enc)
	require.NoError(t, err, "DecodeClientID")
	assert.NotEmpty(t, decoded.IDPClientID, "IDPClientID must be set by Keycloak DCR")
	assert.NotEmpty(t, decoded.IDPClientSecret, "IDPClientSecret must be set by Keycloak DCR")
	assert.Equal(t, resp.ClientSecret, decoded.IDPClientSecret,
		"ClientSecret in response must match the Keycloak-issued secret")

	// Verify the client actually exists in Keycloak via admin API.
	adminToken := mustAdminToken(kcBaseURL)
	data, status, err := adminHTTP("GET",
		kcBaseURL+"/admin/realms/"+kcRealm+"/clients?clientId="+decoded.IDPClientID,
		adminToken, nil)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, "admin GET client")

	var clients []map[string]any
	require.NoError(t, json.Unmarshal(data, &clients))
	require.Len(t, clients, 1, "exactly one Keycloak client should exist with the DCR-assigned ID")
	assert.Equal(t, decoded.IDPClientID, clients[0]["clientId"])
}

// TestKeycloak_ValidateJWT_IssuerValidation verifies that a real Keycloak token
// passes ValidateJWT when validate_issuer is enabled.
func TestKeycloak_ValidateJWT_IssuerValidation(t *testing.T) {
	_, svc := buildService(t, func(idp *config.IDP) {
		idp.ValidateIssuer = true
	})

	tokenResp := mustDirectGrant(t, "openid")
	accessToken := tokenResp["access_token"].(string)

	jwtToken, err := svc.ValidateJWT(context.Background(), accessToken)
	require.NoError(t, err, "ValidateJWT should accept token with correct issuer")
	assert.True(t, jwtToken.Valid)

	issuer, claimsErr := jwtToken.Claims.GetIssuer()
	if claimsErr == nil {
		assert.Contains(t, issuer, kcRealm, "issuer should contain realm name")
	}
}

// TestKeycloak_ValidateJWT_WrongIssuerFails verifies that a token from the
// master realm fails validation when the proxy is configured for mcp-test realm.
func TestKeycloak_ValidateJWT_WrongIssuerFails(t *testing.T) {
	_, svc := buildService(t, func(idp *config.IDP) {
		idp.ValidateIssuer = true
		// Still points at mcp-test realm OIDC discovery — issuer will be the
		// mcp-test realm URL. A token issued by master realm has a different
		// issuer claim, so validation must fail.
	})

	// Get a token from the MASTER realm (different issuer than mcp-test).
	masterToken := mustMasterDirectGrant(t)

	_, err := svc.ValidateJWT(context.Background(), masterToken)
	assert.Error(t, err, "token from master realm must fail issuer check for mcp-test realm")
}

// TestKeycloak_ValidateJWT_AudienceValidation verifies that a token carrying
// the expected audience claim passes validation.
func TestKeycloak_ValidateJWT_AudienceValidation(t *testing.T) {
	_, svc := buildService(t, func(idp *config.IDP) {
		idp.ValidateAudience = true
		idp.Audience = kcAudience
	})

	// Request the mcp:tools scope so Keycloak adds the audience claim.
	tokenResp := mustDirectGrant(t, "openid mcp:tools")
	accessToken := tokenResp["access_token"].(string)

	jwtToken, err := svc.ValidateJWT(context.Background(), accessToken)
	require.NoError(t, err, "ValidateJWT should accept token with correct audience")
	assert.True(t, jwtToken.Valid)
}

// TestKeycloak_ValidateJWT_WrongAudienceFails verifies that a token whose aud
// claim does not match the configured audience is rejected.
func TestKeycloak_ValidateJWT_WrongAudienceFails(t *testing.T) {
	_, svc := buildService(t, func(idp *config.IDP) {
		idp.ValidateAudience = true
		idp.Audience = "http://entirely-different-audience"
	})

	// Token includes mcp:tools scope → aud = kcAudience, not the wrong one.
	tokenResp := mustDirectGrant(t, "openid mcp:tools")
	accessToken := tokenResp["access_token"].(string)

	_, err := svc.ValidateJWT(context.Background(), accessToken)
	assert.Error(t, err, "token with wrong audience must be rejected")
}

// TestKeycloak_ValidateJWT_AudienceAndIssuerTogether verifies that both
// validate_audience and validate_issuer can be enabled simultaneously.
func TestKeycloak_ValidateJWT_AudienceAndIssuerTogether(t *testing.T) {
	_, svc := buildService(t, func(idp *config.IDP) {
		idp.ValidateIssuer = true
		idp.ValidateAudience = true
		idp.Audience = kcAudience
	})

	tokenResp := mustDirectGrant(t, "openid mcp:tools")
	accessToken := tokenResp["access_token"].(string)

	jwtToken, err := svc.ValidateJWT(context.Background(), accessToken)
	require.NoError(t, err, "token with correct issuer and audience must pass")
	assert.True(t, jwtToken.Valid)
}

// TestKeycloak_RefreshToken exercises the full proxy refresh flow using a real
// Keycloak-issued refresh token.
func TestKeycloak_RefreshToken(t *testing.T) {
	enc, svc := buildService(t, nil)

	// Get access + refresh tokens from Keycloak via direct grant.
	tokenResp := mustDirectGrant(t, "openid offline_access")
	idpRefreshToken, ok := tokenResp["refresh_token"].(string)
	require.True(t, ok, "Keycloak must return a refresh_token (check offline_access scope)")
	require.NotEmpty(t, idpRefreshToken)

	// Encode the refresh token into the proxy's opaque format.
	rtData := &RefreshTokenData{Token: idpRefreshToken}
	encryptedRefresh, err := encodeRefreshToken(rtData, enc)
	require.NoError(t, err)

	// Call the proxy's RefreshToken — it should decrypt, call Keycloak, and
	// return new opaque access + refresh tokens.
	newToken, err := svc.RefreshToken(context.Background(), encryptedRefresh)
	require.NoError(t, err, "RefreshToken must succeed with a valid Keycloak refresh token")
	assert.NotEmpty(t, newToken.AccessToken, "new opaque access token must not be empty")
	assert.NotEmpty(t, newToken.RefreshToken, "new opaque refresh token must not be empty")

	// Decrypt the new access token and validate it is a real JWT.
	rawJWT, err := enc.Decrypt(newToken.AccessToken)
	require.NoError(t, err, "new access token must be decryptable")
	parts := strings.Split(string(rawJWT), ".")
	assert.Len(t, parts, 3, "decrypted access token must be a 3-part JWT")

	// Verify the new refresh token is also properly encoded.
	newRTData, err := decodeRefreshToken(newToken.RefreshToken, enc)
	require.NoError(t, err, "new refresh token must be decodable")
	assert.NotEmpty(t, newRTData.Token)
}

// TestKeycloak_DCR_LocalModeUnchanged verifies that local (non-delegate) mode
// still works correctly alongside the Keycloak container (no regression).
func TestKeycloak_DCR_LocalModeUnchanged(t *testing.T) {
	enc, svc := buildService(t, nil) // default: registration_mode = "local"

	resp, err := svc.RegisterClient(context.Background(), &RegisterRequest{
		ClientName:   "local-mode-client",
		RedirectURIs: []string{"http://localhost:9000/cb"},
		GrantTypes:   []string{"authorization_code"},
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.ClientID)
	require.Len(t, resp.ClientSecret, 64, "local mode must produce a 32-byte hex secret")

	decoded, err := DecodeClientID(resp.ClientID, enc)
	require.NoError(t, err)
	assert.Empty(t, decoded.IDPClientID, "local mode must NOT set IDPClientID")
	assert.Empty(t, decoded.IDPClientSecret, "local mode must NOT set IDPClientSecret")
}

// ─── Setup helpers ────────────────────────────────────────────────────────────

// mustStartKeycloak launches the Keycloak container and waits until it accepts
// requests on /realms/master.
func mustStartKeycloak(pool *dockertest.Pool) (*dockertest.Resource, string) {
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "quay.io/keycloak/keycloak",
		Tag:        "26.0",
		Cmd:        []string{"start-dev"},
		Env: []string{
			"KC_BOOTSTRAP_ADMIN_USERNAME=" + kcAdmin,
			"KC_BOOTSTRAP_ADMIN_PASSWORD=" + kcAdminPass,
		},
	}, func(hc *docker.HostConfig) {
		hc.AutoRemove = true
		hc.RestartPolicy = docker.RestartPolicy{Name: "no"}
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "RunWithOptions Keycloak: %v\n", err)
		os.Exit(1)
	}

	hostPort := strings.ReplaceAll(resource.GetHostPort("8080/tcp"), "localhost", "127.0.0.1")
	baseURL := "http://" + hostPort

	if err = resource.Expire(300); err != nil { // 5-minute hard limit
		fmt.Fprintf(os.Stderr, "resource.Expire: %v\n", err)
	}

	pool.MaxWait = 180 * time.Second
	if err = pool.Retry(func() error {
		resp, err := http.Get(baseURL + "/realms/master")
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("not ready yet: HTTP %d", resp.StatusCode)
		}
		return nil
	}); err != nil {
		fmt.Fprintf(os.Stderr, "Keycloak never became ready: %v\n", err)
		os.Exit(1)
	}

	return resource, baseURL
}

// mustSetupRealm creates the mcp-test realm, proxy client, audience scope, and
// test user. Returns the DCR initial access token.
func mustSetupRealm(baseURL, adminToken string) string {
	must := func(desc string, fn func() (int, error)) {
		status, err := fn()
		if err != nil || (status != http.StatusCreated && status != http.StatusNoContent && status != http.StatusOK) {
			fmt.Fprintf(os.Stderr, "setup %s failed: err=%v status=%d\n", desc, err, status)
			os.Exit(1)
		}
	}

	// 1. Create realm.
	must("create realm", func() (int, error) {
		_, s, e := adminHTTP("POST", baseURL+"/admin/realms", adminToken, map[string]any{
			"realm":   kcRealm,
			"enabled": true,
		})
		return s, e
	})

	// 2. Create proxy client with direct-grants enabled.
	must("create proxy client", func() (int, error) {
		_, s, e := adminHTTP("POST", baseURL+"/admin/realms/"+kcRealm+"/clients", adminToken, map[string]any{
			"clientId":                  kcProxyClient,
			"secret":                    kcProxySecret,
			"enabled":                   true,
			"directAccessGrantsEnabled": true,
			"publicClient":              false,
			"redirectUris":              []string{"http://localhost:8080/callback"},
			"protocol":                  "openid-connect",
		})
		return s, e
	})

	// 3. Create "mcp:tools" client scope.
	must("create mcp:tools scope", func() (int, error) {
		_, s, e := adminHTTP("POST", baseURL+"/admin/realms/"+kcRealm+"/client-scopes", adminToken, map[string]any{
			"name":     "mcp:tools",
			"protocol": "openid-connect",
			"attributes": map[string]string{
				"include.in.token.scope": "true",
			},
		})
		return s, e
	})

	// 4. Find scope ID and add audience mapper.
	scopeID := adminGetScopeID(baseURL, adminToken, "mcp:tools")
	must("add audience mapper", func() (int, error) {
		_, s, e := adminHTTP("POST",
			baseURL+"/admin/realms/"+kcRealm+"/client-scopes/"+scopeID+"/protocol-mappers/models",
			adminToken, map[string]any{
				"name":            "aud-mapper",
				"protocol":        "openid-connect",
				"protocolMapper":  "oidc-audience-mapper",
				"consentRequired": false,
				"config": map[string]string{
					"included.custom.audience": kcAudience,
					"access.token.claim":       "true",
					"id.token.claim":           "false",
				},
			})
		return s, e
	})

	// 5. Assign scope as optional to proxy client.
	clientInternalID := adminGetClientID(baseURL, adminToken, kcProxyClient)
	must("assign scope to client", func() (int, error) {
		_, s, e := adminHTTP("PUT",
			baseURL+"/admin/realms/"+kcRealm+"/clients/"+clientInternalID+"/optional-client-scopes/"+scopeID,
			adminToken, nil)
		return s, e
	})

	// 6. Create test user.
	must("create test user", func() (int, error) {
		_, s, e := adminHTTP("POST", baseURL+"/admin/realms/"+kcRealm+"/users", adminToken, map[string]any{
			"username": kcTestUser,
			"enabled":  true,
		})
		return s, e
	})

	// 7. Set test user password.
	userID := adminGetUserID(baseURL, adminToken, kcTestUser)
	must("set user password", func() (int, error) {
		_, s, e := adminHTTP("PUT",
			baseURL+"/admin/realms/"+kcRealm+"/users/"+userID+"/reset-password",
			adminToken, map[string]any{
				"type":      "password",
				"value":     kcTestUserPass,
				"temporary": false,
			})
		return s, e
	})

	// 8. Create DCR initial access token.
	data, status, err := adminHTTP("POST",
		baseURL+"/admin/realms/"+kcRealm+"/clients-initial-access",
		adminToken, map[string]any{
			"expiration": 86400,
			"count":      20,
		})
	if err != nil || status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "create initial access token failed: err=%v status=%d\n", err, status)
		os.Exit(1)
	}
	var iatResp map[string]any
	if err := json.Unmarshal(data, &iatResp); err != nil {
		fmt.Fprintf(os.Stderr, "parse initial access token: %v\n", err)
		os.Exit(1)
	}
	token, ok := iatResp["token"].(string)
	if !ok || token == "" {
		fmt.Fprintf(os.Stderr, "initial access token empty in response: %v\n", iatResp)
		os.Exit(1)
	}
	return token
}

// ─── Per-test helpers ─────────────────────────────────────────────────────────

// buildService constructs a proxy auth.Service backed by the running Keycloak
// container. extraConfig optionally mutates the IDP config before construction.
func buildService(t *testing.T, extraConfig func(*config.IDP)) (utility.Encryption, Service) {
	t.Helper()

	cfg := config.Config{
		Proxy: config.Proxy{
			BaseURL:    "http://localhost:8080",
			ListenAddr: ":8080",
			LogLevel:   "error",
			LogFormat:  "json",
		},
		IDP: config.IDP{
			ClientID:               kcProxyClient,
			ClientSecret:           kcProxySecret,
			OpenIDConfigurationURL: kcBaseURL + "/realms/" + kcRealm + "/.well-known/openid-configuration",
			Scopes:                 []string{"openid", "offline_access"},
		},
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{MasterKey: kcEncKey},
	}

	if extraConfig != nil {
		extraConfig(&cfg.IDP)
	}

	enc, err := utility.NewEncryption(&cfg)
	require.NoError(t, err)

	svc, err := New(cfg, enc)
	require.NoError(t, err)

	return enc, svc
}

// mustDirectGrant obtains tokens from the mcp-test realm via Resource Owner
// Password Credentials grant.
func mustDirectGrant(t *testing.T, scopes string) map[string]any {
	t.Helper()

	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {kcProxyClient},
		"client_secret": {kcProxySecret},
		"username":      {kcTestUser},
		"password":      {kcTestUserPass},
		"scope":         {scopes},
	}
	resp, err := http.PostForm(
		kcBaseURL+"/realms/"+kcRealm+"/protocol/openid-connect/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode, "direct grant token request")

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	require.Contains(t, result, "access_token", "token response: %v", result)
	return result
}

// mustMasterDirectGrant obtains a token from the MASTER realm (different issuer
// than the mcp-test realm — used for negative issuer validation tests).
func mustMasterDirectGrant(t *testing.T) string {
	t.Helper()

	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {kcAdmin},
		"password":   {kcAdminPass},
	}
	resp, err := http.PostForm(
		kcBaseURL+"/realms/master/protocol/openid-connect/token", form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	token, ok := result["access_token"].(string)
	require.True(t, ok)
	return token
}

// mustAdminToken fetches a fresh Keycloak admin bearer token.
func mustAdminToken(baseURL string) string {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {"admin-cli"},
		"username":   {kcAdmin},
		"password":   {kcAdminPass},
	}
	resp, err := http.PostForm(baseURL+"/realms/master/protocol/openid-connect/token", form)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get admin token: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		fmt.Fprintf(os.Stderr, "decode admin token: %v\n", err)
		os.Exit(1)
	}
	token, ok := result["access_token"].(string)
	if !ok {
		fmt.Fprintf(os.Stderr, "admin token missing: %v\n", result)
		os.Exit(1)
	}
	return token
}

// ─── Keycloak Admin API helpers ───────────────────────────────────────────────

// adminHTTP makes an authenticated JSON request to the Keycloak admin API.
func adminHTTP(method, rawURL, token string, body any) ([]byte, int, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, 0, fmt.Errorf("marshal body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}

	req, err := http.NewRequest(method, rawURL, bodyReader)
	if err != nil {
		return nil, 0, fmt.Errorf("new request: %w", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	return data, resp.StatusCode, err
}

func adminGetScopeID(baseURL, adminToken, name string) string {
	data, status, err := adminHTTP("GET", baseURL+"/admin/realms/"+kcRealm+"/client-scopes", adminToken, nil)
	if err != nil || status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "list scopes: err=%v status=%d\n", err, status)
		os.Exit(1)
	}
	var scopes []map[string]any
	if err := json.Unmarshal(data, &scopes); err != nil {
		fmt.Fprintf(os.Stderr, "parse scopes: %v\n", err)
		os.Exit(1)
	}
	for _, s := range scopes {
		if s["name"] == name {
			id, _ := s["id"].(string)
			return id
		}
	}
	fmt.Fprintf(os.Stderr, "scope %q not found\n", name)
	os.Exit(1)
	return ""
}

func adminGetClientID(baseURL, adminToken, clientID string) string {
	data, status, err := adminHTTP("GET",
		baseURL+"/admin/realms/"+kcRealm+"/clients?clientId="+url.QueryEscape(clientID),
		adminToken, nil)
	if err != nil || status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "list clients: err=%v status=%d\n", err, status)
		os.Exit(1)
	}
	var clients []map[string]any
	if err := json.Unmarshal(data, &clients); err != nil || len(clients) == 0 {
		fmt.Fprintf(os.Stderr, "client %q not found\n", clientID)
		os.Exit(1)
	}
	id, _ := clients[0]["id"].(string)
	return id
}

func adminGetUserID(baseURL, adminToken, username string) string {
	data, status, err := adminHTTP("GET",
		baseURL+"/admin/realms/"+kcRealm+"/users?username="+url.QueryEscape(username),
		adminToken, nil)
	if err != nil || status != http.StatusOK {
		fmt.Fprintf(os.Stderr, "list users: err=%v status=%d\n", err, status)
		os.Exit(1)
	}
	var users []map[string]any
	if err := json.Unmarshal(data, &users); err != nil || len(users) == 0 {
		fmt.Fprintf(os.Stderr, "user %q not found\n", username)
		os.Exit(1)
	}
	id, _ := users[0]["id"].(string)
	return id
}
