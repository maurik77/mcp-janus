package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/utility"
	"net/http"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

const (
	clientSecretSize   = 32
	defaultTokenTTL    = 24 * time.Hour
	defaultTokenMaxTTL = 7 * 24 * time.Hour
)

type ProxyAuthHandler struct {
	config              config.Config
	oauthConfig         *oauth2.Config
	encryption          utility.Encryption
	openidConfiguration *OpenIDConfiguration
	jwks                *JWKS
	jwksMu              sync.RWMutex
	tracer              trace.Tracer
	httpClient          *http.Client
	cimdCache           *cimdCache
	cimdFetcher         func(url string, client *http.Client, cache *cimdCache) (*ClientMetadataDocument, error)
	jtiStore            *jtiStore
}

// withRetry calls fn up to attempts times, waiting delay between failures.
func withRetry[T any](attempts int, delay time.Duration, fn func() (T, error)) (T, error) {
	var err error
	for i := range attempts {
		var result T
		result, err = fn()
		if err == nil {
			return result, nil
		}
		if i < attempts-1 {
			utility.Logger.Warn().Err(err).
				Int("attempt", i+1).
				Int("max", attempts).
				Msg("fetch failed, retrying")
			time.Sleep(delay)
		}
	}
	var zero T
	return zero, err
}

func New(cfg config.Config, encryption utility.Encryption) (Service, error) {
	retryAttempts := cfg.IDP.FetchRetryAttempts
	if retryAttempts <= 0 {
		retryAttempts = 3
	}
	retryDelay := cfg.IDP.FetchRetryDelay
	if retryDelay <= 0 {
		retryDelay = 2 * time.Second
	}

	openidConfiguration, err := withRetry(retryAttempts, retryDelay, func() (*OpenIDConfiguration, error) {
		return fetchOpenIDConfiguration(cfg.IDP.OpenIDConfigurationURL, cfg.IDP.SkipTLSVerify)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenID configuration after %d attempts: %w", retryAttempts, err)
	}

	jwks, err := withRetry(retryAttempts, retryDelay, func() (*JWKS, error) {
		return fetchJWKS(openidConfiguration.JWKSEndpoint, cfg.IDP.SkipTLSVerify)
	})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS after %d attempts: %w", retryAttempts, err)
	}

	oauthConfig := &oauth2.Config{
		ClientID:     cfg.IDP.ClientID,
		ClientSecret: cfg.IDP.ClientSecret,
		RedirectURL:  cfg.Proxy.BaseURL + "/callback",
		Endpoint: oauth2.Endpoint{
			AuthURL:  openidConfiguration.AuthorizationEndpoint,
			TokenURL: openidConfiguration.TokenEndpoint,
		},
		Scopes: cfg.IDP.Scopes,
	}

	handler := &ProxyAuthHandler{
		config:              cfg,
		oauthConfig:         oauthConfig,
		encryption:          encryption,
		openidConfiguration: openidConfiguration,
		jwks:                jwks,
		tracer:              otel.Tracer("mcp-proxy.auth"),
		httpClient:          newHTTPClient(cfg.IDP.SkipTLSVerify),
		cimdCache:           &cimdCache{entries: make(map[string]cimdCacheEntry)},
		cimdFetcher:         fetchAndValidateCIMD,
		jtiStore:            newJTIStore(),
	}

	utility.Logger.Info().
		Str("issuer", openidConfiguration.Issuer).
		Int("jwks_keys", len(jwks.Keys)).
		Msg("Auth service initialized")
	utility.Logger.Debug().
		Str("idp_client_id", cfg.IDP.ClientID).
		Str("redirect_url", cfg.Proxy.BaseURL+"/callback").
		Str("auth_url", openidConfiguration.AuthorizationEndpoint).
		Str("token_url", openidConfiguration.TokenEndpoint).
		Strs("scopes", cfg.IDP.Scopes).
		Msg("[DEBUG] New: oauth config")

	return handler, nil
}

func (h *ProxyAuthHandler) RegisterClient(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	_, span := h.tracer.Start(ctx, "auth.RegisterClient")
	defer span.End()

	if req != nil {
		utility.Logger.Debug().
			Str("client_name", req.ClientName).
			Strs("redirect_uris", req.RedirectURIs).
			Strs("grant_types", req.GrantTypes).
			Strs("response_types", req.ResponseTypes).
			Str("token_endpoint_auth_method", req.TokenEndpointAuthMethod).
			Msg("[DEBUG] RegisterClient: request received")
		if len(req.RedirectURIs) > 0 {
			span.SetAttributes(attribute.Int("redirect_uris.count", len(req.RedirectURIs)))
		}
	}

	clientId, secret, err := generateClientID(req, h.encryption)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to generate client ID")
		utility.Logger.Error().Err(err).Msg("Failed to generate client ID")
		return nil, err
	}

	span.SetAttributes(attribute.String("client.id", clientId))
	span.SetStatus(codes.Ok, "Client registered successfully")

	res := RegisterResponse{
		ClientID:                clientId,
		ClientSecret:            secret,
		ClientIDIssuedAt:        time.Now().Unix(),
		ClientSecretExpiresAt:   0,
		ClientName:              req.ClientName,
		RedirectURIs:            req.RedirectURIs,
		GrantTypes:              grantTypesOrDefault(req.GrantTypes),
		ResponseTypes:           responseTypesOrDefault(req.ResponseTypes),
		TokenEndpointAuthMethod: tokenAuthMethodOrDefault(req.TokenEndpointAuthMethod),
	}

	utility.Logger.Info().Str("client_id", clientId).Msg("Client registered successfully")
	utility.Logger.Debug().
		Str("client_id", clientId).
		Msg("[DEBUG] RegisterClient: credentials issued")

	return &res, nil
}

func grantTypesOrDefault(v []string) []string {
	if len(v) == 0 {
		return []string{"authorization_code"}
	}
	return v
}

func responseTypesOrDefault(v []string) []string {
	if len(v) == 0 {
		return []string{"code"}
	}
	return v
}

func tokenAuthMethodOrDefault(v string) string {
	if v == "" {
		return "none"
	}
	return v
}

func (h *ProxyAuthHandler) AuthenticateRequest(ctx context.Context, req *AuthenticateRequest) (string, error) {
	_, span := h.tracer.Start(ctx, "auth.AuthenticateRequest")
	defer span.End()

	if req == nil || req.ClientID == "" {
		span.SetStatus(codes.Error, "Invalid request")
		utility.Logger.Warn().Msg("AuthenticateRequest: missing client_id")
		return "", fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("client_id", req.ClientID).
		Str("redirect_uri", req.RedirectURI).
		Str("state", req.State).
		Str("code_challenge", req.CodeChallenge).
		Str("code_challenge_method", req.CodeChallengeMethod).
		Msg("[DEBUG] AuthenticateRequest: request received")

	span.SetAttributes(
		attribute.String("client.id", req.ClientID),
		attribute.String("redirect_uri", req.RedirectURI),
		attribute.String("code_challenge_method", req.CodeChallengeMethod),
	)

	portInsensitive := h.config.Proxy.CIMDLocalhostPortInsensitive
	if err := h.assertRedirectURI(req.ClientID, req.RedirectURI, portInsensitive); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Redirect URI validation failed")
		return "", err
	}

	stateData := StateData{
		OriginalState: req.State,
		RedirectURI:   req.RedirectURI,
		ClientID:      req.ClientID,
		Resource:      req.Resource,
	}

	encryptedState, err := stateData.Encode(h.encryption)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt state")
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("AuthenticateRequest: failed to encrypt state")
		return "", fmt.Errorf("invalid_request")
	}
	utility.Logger.Debug().
		Str("encrypted_state", encryptedState).
		Msg("[DEBUG] AuthenticateRequest: state encrypted")

	// Redirect to real IdP
	authParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", req.CodeChallengeMethod),
		oauth2.SetAuthURLParam("redirect_uri", h.config.Proxy.BaseURL+"/callback"),
	}
	if req.Resource != "" {
		authParams = append(authParams, oauth2.SetAuthURLParam("resource", req.Resource))
	}
	authURL := h.oauthConfig.AuthCodeURL(encryptedState, authParams...)

	span.SetStatus(codes.Ok, "Authentication request successful")
	utility.Logger.Info().Str("auth_url", authURL).Msg("Authentication request successful")

	return authURL, nil
}

func (h *ProxyAuthHandler) ManageAuthorizationCode(ctx context.Context, req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error) {
	if req == nil {
		utility.Logger.Warn().Msg("ManageAuthorizationCode: nil request")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("code", req.Code).
		Str("encrypted_state", req.State).
		Msg("[DEBUG] ManageAuthorizationCode: request received")

	stateData, err := DecodeStateData(req.State, h.encryption)
	if err != nil {
		utility.Logger.Warn().Err(err).Msg("ManageAuthorizationCode: failed to decode state")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("original_state", stateData.OriginalState).
		Str("client_id", stateData.ClientID).
		Str("redirect_uri", stateData.RedirectURI).
		Msg("[DEBUG] ManageAuthorizationCode: decoded state")

	portInsensitive := h.config.Proxy.CIMDLocalhostPortInsensitive

	// Validate redirect URI against registered client or CIMD document
	if err := h.assertRedirectURI(stateData.ClientID, stateData.RedirectURI, portInsensitive); err != nil {
		utility.Logger.Warn().Err(err).Str("client_id", stateData.ClientID).Msg("ManageAuthorizationCode: redirect_uri validation failed")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	// Validate redirect URI is a well-formed absolute URL with http(s) scheme
	redirectURL, err := url.Parse(stateData.RedirectURI)
	if err != nil {
		utility.Logger.Warn().Err(err).Str("redirect_uri", stateData.RedirectURI).Msg("ManageAuthorizationCode: invalid redirect_uri")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	if redirectURL.Host == "" || (redirectURL.Scheme != "http" && redirectURL.Scheme != "https") {
		utility.Logger.Warn().Str("redirect_uri", stateData.RedirectURI).Msg("ManageAuthorizationCode: redirect_uri has invalid scheme or missing host")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	res := &AuthorizationCodeData{
		State: stateData.OriginalState,
		Code:  req.Code,
	}

	// Append iss to redirect (RFC 9207 §2): binds the auth response to this AS.
	issuer := h.config.Proxy.Issuer
	if issuer == "" {
		issuer = h.config.Proxy.BaseURL
	}
	q := redirectURL.Query()
	q.Set("iss", issuer)
	redirectURL.RawQuery = q.Encode()

	utility.Logger.Info().
		Str("client_id", stateData.ClientID).
		Str("redirect_uri", redirectURL.String()).
		Msg("Authorization code dispatched to client")

	return res, redirectURL, nil
}

func (h *ProxyAuthHandler) RetrieveAccessToken(ctx context.Context, req *AccessTokenRequest) (*oauth2.Token, error) {
	ctx, span := h.tracer.Start(ctx, "auth.RetrieveAccessToken")
	defer span.End()

	if req == nil {
		span.SetStatus(codes.Error, "Invalid request")
		utility.Logger.Warn().Msg("RetrieveAccessToken: nil request")
		return nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("client_id", req.ClientID).
		Str("code", req.Code).
		Str("code_verifier", req.CodeVerifier).
		Str("redirect_uri", req.RedirectURI).
		Str("grant_type", req.GrantTypes).
		Msg("[DEBUG] RetrieveAccessToken: request received")

	if req.Code == "" {
		span.SetStatus(codes.Error, "Missing required parameters")
		utility.Logger.Warn().Str("client_id", req.ClientID).Msg("RetrieveAccessToken: missing authorization code")
		return nil, fmt.Errorf("invalid_request")
	}

	if req.ClientID != "" {
		span.SetAttributes(attribute.String("client.id", req.ClientID))
		if err := h.validateClientAuth(ctx, req); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Client authentication failed")
			utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: client authentication failed")
			return nil, err
		}
	}

	// Exchange with real IdP
	httpClient := h.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	exchangeParams := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("grant_type", req.GrantTypes),
		oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier),
	}
	if req.Resource != "" {
		exchangeParams = append(exchangeParams, oauth2.SetAuthURLParam("resource", req.Resource))
	}
	token, err := h.oauthConfig.Exchange(oauthCtx, req.Code, exchangeParams...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Token exchange failed")
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: token exchange with IdP failed")
		return nil, fmt.Errorf("invalid_request")
	}

	span.AddEvent("Token received from IdP")

	if h.config.Proxy.TokenBehavior == config.TokenBehaviorSelfIssued {
		result, siErr := h.issueSelfIssuedTokens(ctx, token)
		if siErr != nil {
			span.RecordError(siErr)
			span.SetStatus(codes.Error, "Failed to issue self-issued token")
			return nil, siErr
		}
		span.SetStatus(codes.Ok, "Self-issued token exchange successful")
		return result, nil
	}

	// Validate JWT signature at issuance — the only point where JWKS is checked.
	// Per-request middleware relies on AEAD integrity and skips this call.
	if _, err := h.ValidateJWT(ctx, token.AccessToken); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "IdP JWT validation failed at issuance")
		utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: IdP JWT validation failed")
		return nil, fmt.Errorf("invalid_request")
	}

	opaqueToken, err := h.encryptTokenPair(token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: token encryption failed")
		return nil, err
	}

	span.SetStatus(codes.Ok, "Token exchange successful")
	utility.Logger.Info().
		Str("client_id", req.ClientID).
		Str("token_type", opaqueToken.TokenType).
		Time("expiry", opaqueToken.Expiry).
		Msg("Access token issued to client")

	return opaqueToken, nil
}

func (h *ProxyAuthHandler) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*oauth2.Token, error) {
	ctx, span := h.tracer.Start(ctx, "auth.RefreshToken")
	defer span.End()

	if req == nil {
		span.SetStatus(codes.Error, "Invalid request")
		utility.Logger.Warn().Msg("RefreshToken: nil request")
		return nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("grant_type", req.GrantType).
		Str("client_id", req.ClientID).
		Str("encrypted_refresh_token", req.RefreshToken).
		Msg("[DEBUG] RefreshToken: request received")

	if req.RefreshToken == "" {
		span.SetStatus(codes.Error, "Missing refresh token")
		utility.Logger.Warn().Msg("RefreshToken: empty refresh token")
		return nil, fmt.Errorf("invalid_request")
	}

	if req.ClientID != "" {
		// Only validate secret when the client provided one (confidential clients).
		// Public clients (token_endpoint_auth_method=none) rely on PKCE instead.
		if err := h.validateClientCredentials(req.ClientID, req.ClientSecret); err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Invalid client credentials")
			utility.Logger.Warn().Str("client_id", req.ClientID).Msg("RefreshToken: invalid client credentials")
			return nil, err
		}
	}

	if h.config.Proxy.TokenBehavior == config.TokenBehaviorSelfIssued {
		result, siErr := h.refreshSelfIssuedToken(req)
		if siErr != nil {
			span.RecordError(siErr)
			span.SetStatus(codes.Error, "Self-issued refresh failed")
			return nil, siErr
		}
		span.SetStatus(codes.Ok, "Self-issued token refreshed")
		return result, nil
	}

	decryptedRefreshToken, err := h.encryption.Decrypt(req.RefreshToken)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decrypt refresh token")
		utility.Logger.Warn().Err(err).Msg("RefreshToken: failed to decrypt refresh token")
		return nil, fmt.Errorf("invalid_request")
	}

	refreshTokenValue := string(decryptedRefreshToken)
	utility.Logger.Debug().
		Str("decrypted_refresh_token", refreshTokenValue).
		Msg("[DEBUG] RefreshToken: decrypted refresh token")

	if refreshTokenValue == "" {
		span.SetStatus(codes.Error, "Empty refresh token after decryption")
		utility.Logger.Warn().Msg("RefreshToken: refresh token empty after decryption")
		return nil, fmt.Errorf("invalid_request")
	}

	httpClient := h.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	tokenSource := h.oauthConfig.TokenSource(oauthCtx, &oauth2.Token{
		RefreshToken: refreshTokenValue,
	})

	token, err := tokenSource.Token()
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Refresh token exchange failed")
		utility.Logger.Error().Err(err).Msg("RefreshToken: token exchange with IdP failed")
		return nil, fmt.Errorf("invalid_request")
	}

	span.AddEvent("Refresh token received from IdP")

	if token.RefreshToken == "" {
		token.RefreshToken = refreshTokenValue
	}

	// Validate JWT signature at refresh — same boundary check as issuance.
	if _, err := h.ValidateJWT(ctx, token.AccessToken); err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "IdP JWT validation failed at refresh")
		utility.Logger.Warn().Err(err).Msg("RefreshToken: IdP JWT validation failed")
		return nil, fmt.Errorf("invalid_request")
	}

	opaqueToken, err := h.encryptTokenPair(token)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
		utility.Logger.Error().Err(err).Msg("RefreshToken: token encryption failed")
		return nil, err
	}

	span.SetStatus(codes.Ok, "Refresh token exchange successful")
	utility.Logger.Info().
		Str("token_type", opaqueToken.TokenType).
		Time("expiry", opaqueToken.Expiry).
		Msg("Refresh token exchanged, new access token issued")

	return opaqueToken, nil
}

func generateClientID(req *RegisterRequest, encryption utility.Encryption) (string, string, error) {
	secretBytes := make([]byte, clientSecretSize)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	clientSecret := hex.EncodeToString(secretBytes)

	clientData := ClientIDData{
		RedirectURIs: req.RedirectURIs,
		Secret:       clientSecret,
	}

	utility.Logger.Debug().
		Strs("redirect_uris", clientData.RedirectURIs).
		Msg("[DEBUG] generateClientID: client data before encoding")

	encryptedClientID, err := clientData.Encode(encryption)

	utility.Logger.Debug().
		Str("encrypted_client_id", encryptedClientID).
		Msg("[DEBUG] generateClientID: encrypted client_id")

	return encryptedClientID, clientSecret, err
}

// assertRedirectURI validates that redirectURI is registered for clientID.
// Supports both CIMD URL client IDs and opaque encrypted client IDs.
func (h *ProxyAuthHandler) assertRedirectURI(clientID, redirectURI string, portInsensitive bool) error {
	if isURLClientID(clientID) {
		doc, err := h.cimdFetcher(clientID, h.httpClient, h.cimdCache)
		if err != nil {
			utility.Logger.Warn().Err(err).Str("client_id", clientID).Msg("assertRedirectURI: CIMD fetch failed")
			return fmt.Errorf("invalid_client")
		}
		if !redirectURIMatchesRegistered(redirectURI, doc.RedirectURIs, portInsensitive) {
			utility.Logger.Warn().Str("client_id", clientID).Str("redirect_uri", redirectURI).Msg("assertRedirectURI: redirect_uri not in CIMD document")
			return fmt.Errorf("invalid_request")
		}
		return nil
	}
	clientData, err := DecodeClientID(clientID, h.encryption)
	if err != nil {
		utility.Logger.Warn().Err(err).Str("client_id", clientID).Msg("assertRedirectURI: failed to decode client_id")
		return fmt.Errorf("invalid_request")
	}
	utility.Logger.Debug().
		Strs("registered_redirect_uris", clientData.RedirectURIs).
		Str("redirect_uri", redirectURI).
		Msg("[DEBUG] assertRedirectURI: decoded client data")
	if !slices.Contains(clientData.RedirectURIs, redirectURI) {
		utility.Logger.Warn().Str("client_id", clientID).Str("redirect_uri", redirectURI).Msg("assertRedirectURI: redirect_uri not registered for client")
		return fmt.Errorf("invalid_request")
	}
	return nil
}

// validateClientAuth authenticates the client at the token endpoint.
// Supports three modes:
//  1. CIMD URL client_id with private_key_jwt assertion (ChatGPT pattern)
//  2. CIMD URL client_id without assertion → public client, PKCE-only, no secret needed
//  3. Opaque encrypted client_id → validate stored secret
func (h *ProxyAuthHandler) validateClientAuth(ctx context.Context, req *AccessTokenRequest) error {
	const assertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

	if isURLClientID(req.ClientID) {
		if req.ClientAssertionType == assertionType && req.ClientAssertion != "" {
			return h.validatePrivateKeyJWT(ctx, req)
		}
		// Public CIMD client — PKCE is the only authentication factor; no secret needed.
		return nil
	}

	// Opaque encrypted client_id (DCR path).
	clientData, err := DecodeClientID(req.ClientID, h.encryption)
	if err != nil {
		return fmt.Errorf("invalid_request")
	}
	if clientData.Secret != req.ClientSecret {
		return fmt.Errorf("invalid_client")
	}
	return nil
}

// validateClientCredentials decodes the opaque client_id and, when a secret is
// provided, verifies it matches the stored value. Public clients (PKCE-only)
// pass an empty clientSecret and skip the comparison.
func (h *ProxyAuthHandler) validateClientCredentials(clientID, clientSecret string) error {
	clientData, err := DecodeClientID(clientID, h.encryption)
	if err != nil {
		return fmt.Errorf("invalid_request")
	}
	utility.Logger.Debug().
		Str("client_id", clientID).
		Bool("match", clientData.Secret == clientSecret).
		Msg("[DEBUG] validateClientCredentials: client secret comparison")
	if clientSecret != "" && clientData.Secret != clientSecret {
		return fmt.Errorf("invalid_request")
	}
	return nil
}

// validatePrivateKeyJWT verifies a client_assertion JWT per RFC 7523.
// It fetches the client's JWKS from the CIMD document's jwks_uri, then validates:
//   - iss == sub == client_id
//   - aud contains the token endpoint URL
//   - exp not in the past
//   - jti not previously seen (replay protection)
func (h *ProxyAuthHandler) validatePrivateKeyJWT(_ context.Context, req *AccessTokenRequest) error {
	doc, err := h.cimdFetcher(req.ClientID, h.httpClient, h.cimdCache)
	if err != nil {
		return fmt.Errorf("invalid_client")
	}
	if doc.JwksURI == "" {
		utility.Logger.Warn().Str("client_id", req.ClientID).Msg("validatePrivateKeyJWT: CIMD doc has no jwks_uri")
		return fmt.Errorf("invalid_client")
	}

	jwks, err := fetchJWKS(doc.JwksURI, false)
	if err != nil {
		utility.Logger.Warn().Err(err).Str("jwks_uri", doc.JwksURI).Msg("validatePrivateKeyJWT: failed to fetch client JWKS")
		return fmt.Errorf("invalid_client")
	}

	tokenEndpoint := h.config.Proxy.BaseURL + "/token"

	token, err := jwt.Parse(req.ClientAssertion, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key := jwks.GetKeyByKID(kid)
		if key == nil {
			return nil, fmt.Errorf("key %q not found in client JWKS", kid)
		}
		return key, nil
	})
	if err != nil || !token.Valid {
		utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("validatePrivateKeyJWT: JWT parse/validation failed")
		return fmt.Errorf("invalid_client")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid_client")
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	if iss != req.ClientID || sub != req.ClientID {
		utility.Logger.Warn().Str("iss", iss).Str("sub", sub).Str("client_id", req.ClientID).Msg("validatePrivateKeyJWT: iss/sub mismatch")
		return fmt.Errorf("invalid_client")
	}

	if !jwtAudienceContains(claims, tokenEndpoint) {
		utility.Logger.Warn().Str("client_id", req.ClientID).Msg("validatePrivateKeyJWT: audience mismatch")
		return fmt.Errorf("invalid_client")
	}

	jti, _ := claims["jti"].(string)
	if jti == "" {
		utility.Logger.Warn().Str("client_id", req.ClientID).Msg("validatePrivateKeyJWT: missing jti")
		return fmt.Errorf("invalid_client")
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return fmt.Errorf("invalid_client")
	}
	if h.jtiStore.Seen(jti, exp.Time) {
		utility.Logger.Warn().Str("jti", jti).Msg("validatePrivateKeyJWT: replayed jti")
		return fmt.Errorf("invalid_client")
	}

	return nil
}

// encryptTokenPair returns a copy of token with AccessToken and RefreshToken
// replaced by their AES-256-GCM opaque equivalents.
func (h *ProxyAuthHandler) encryptTokenPair(token *oauth2.Token) (*oauth2.Token, error) {
	encAT, err := h.encryption.Encrypt([]byte(token.AccessToken))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt access token: %w", err)
	}
	encRT, err := h.encryption.Encrypt([]byte(token.RefreshToken))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt refresh token: %w", err)
	}
	result := *token
	result.AccessToken = encAT
	result.RefreshToken = encRT
	return &result, nil
}

func (h *ProxyAuthHandler) ValidateJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
	utility.Logger.Debug().
		Str("token", tokenString).
		Msg("[DEBUG] ValidateJWT: validating token")

	keyFunc := func(token *jwt.Token) (any, error) {
		kid, ok := token.Header["kid"].(string)
		utility.Logger.Debug().
			Str("alg", fmt.Sprintf("%v", token.Header["alg"])).
			Str("kid", kid).
			Bool("kid_present", ok).
			Msg("[DEBUG] ValidateJWT: token header")
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		// Try cached JWKS first
		h.jwksMu.RLock()
		key := h.jwks.GetKeyByKID(kid)
		h.jwksMu.RUnlock()
		if key != nil {
			utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key found in cache")
			return key, nil
		}

		utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key not in cache, refreshing JWKS")

		// Cache miss — IdP may have rotated keys; refresh JWKS
		if err := h.refreshJWKS(); err != nil {
			utility.Logger.Warn().Err(err).Str("kid", kid).Msg("Failed to refresh JWKS")
			return nil, fmt.Errorf("key not found and JWKS refresh failed: %w", err)
		}

		h.jwksMu.RLock()
		key = h.jwks.GetKeyByKID(kid)
		h.jwksMu.RUnlock()
		if key != nil {
			utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key found after JWKS refresh")
			return key, nil
		}

		return nil, fmt.Errorf("key %q not found after JWKS refresh", kid)
	}

	options := []jwt.ParserOption{}
	if h.config.IDP.JWTLeeway > 0 {
		options = append(options, jwt.WithLeeway(h.config.IDP.JWTLeeway))
	}
	utility.Logger.Debug().
		Dur("leeway", h.config.IDP.JWTLeeway).
		Msg("[DEBUG] ValidateJWT: parser options")

	token, err := jwt.Parse(tokenString, keyFunc, options...)
	if err != nil {
		utility.Logger.Debug().Err(err).Msg("[DEBUG] ValidateJWT: parse/validation failed")
		return nil, err
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		utility.Logger.Debug().
			Any("claims", map[string]any(claims)).
			Msg("[DEBUG] ValidateJWT: token claims")
	}

	return token, nil
}

// issueSelfIssuedTokens validates the IdP JWT once, extracts mapped claims,
// and creates a pair of AES-256-GCM opaque tokens with a Janus-controlled TTL.
func (h *ProxyAuthHandler) issueSelfIssuedTokens(ctx context.Context, idpToken *oauth2.Token) (*oauth2.Token, error) {
	jwtToken, err := h.ValidateJWT(ctx, idpToken.AccessToken)
	if err != nil || !jwtToken.Valid {
		utility.Logger.Warn().Err(err).Msg("issueSelfIssuedTokens: IdP JWT validation failed")
		return nil, fmt.Errorf("invalid_request")
	}

	claims, ok := jwtToken.Claims.(jwt.MapClaims)
	if !ok {
		utility.Logger.Warn().Msg("issueSelfIssuedTokens: failed to parse JWT claims as MapClaims")
		return nil, fmt.Errorf("invalid_request")
	}

	mappedClaims := make(map[string]string)
	for source, dest := range h.config.IDP.ClaimsMapping {
		if value, exists := claims[source]; exists {
			if strValue, ok := value.(string); ok {
				mappedClaims[dest] = strValue
			}
		}
	}

	now := time.Now()
	ttl := h.config.Proxy.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}
	maxTTL := h.config.Proxy.TokenMaxTTL
	if maxTTL <= 0 {
		maxTTL = defaultTokenMaxTTL
	}

	atData := &SelfIssuedTokenData{
		Type:      "si",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
		Claims:    mappedClaims,
	}
	rtData := &SelfIssuedTokenData{
		Type:      "si",
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(maxTTL).Unix(),
		Claims:    mappedClaims,
	}

	encAT, err := atData.Encode(h.encryption)
	if err != nil {
		utility.Logger.Error().Err(err).Msg("issueSelfIssuedTokens: failed to encrypt access token")
		return nil, err
	}
	encRT, err := rtData.Encode(h.encryption)
	if err != nil {
		utility.Logger.Error().Err(err).Msg("issueSelfIssuedTokens: failed to encrypt refresh token")
		return nil, err
	}

	utility.Logger.Info().Time("expiry", now.Add(ttl)).Msg("Self-issued access token issued")

	return &oauth2.Token{
		AccessToken:  encAT,
		RefreshToken: encRT,
		TokenType:    "Bearer",
		Expiry:       now.Add(ttl),
	}, nil
}

// refreshSelfIssuedToken re-issues the access token from a self-issued refresh token
// without contacting the IdP. The refresh token is returned unchanged (it is immutable).
func (h *ProxyAuthHandler) refreshSelfIssuedToken(req *RefreshTokenRequest) (*oauth2.Token, error) {
	si, err := DecodeSelfIssuedToken(req.RefreshToken, h.encryption)
	if err != nil {
		utility.Logger.Warn().Err(err).Msg("refreshSelfIssuedToken: failed to decode refresh token")
		return nil, fmt.Errorf("invalid_grant")
	}

	now := time.Now()
	if now.Unix() >= si.ExpiresAt {
		utility.Logger.Warn().Msg("refreshSelfIssuedToken: refresh token expired")
		return nil, fmt.Errorf("invalid_grant")
	}

	ttl := h.config.Proxy.TokenTTL
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}

	newExpAt := min(now.Add(ttl).Unix(), si.ExpiresAt)

	newAT := &SelfIssuedTokenData{
		Type:      "si",
		IssuedAt:  si.IssuedAt,
		ExpiresAt: newExpAt,
		Claims:    si.Claims,
	}

	encAT, err := newAT.Encode(h.encryption)
	if err != nil {
		utility.Logger.Error().Err(err).Msg("refreshSelfIssuedToken: failed to encrypt new access token")
		return nil, err
	}

	utility.Logger.Info().Time("expiry", time.Unix(newExpAt, 0)).Msg("Self-issued token refreshed")

	return &oauth2.Token{
		AccessToken:  encAT,
		RefreshToken: req.RefreshToken,
		TokenType:    "Bearer",
		Expiry:       time.Unix(newExpAt, 0),
	}, nil
}

// refreshJWKS re-fetches the JWKS from the IdP.
func (h *ProxyAuthHandler) refreshJWKS() error {
	jwks, err := fetchJWKS(h.openidConfiguration.JWKSEndpoint, h.config.IDP.SkipTLSVerify)
	if err != nil {
		return err
	}
	h.jwksMu.Lock()
	h.jwks = jwks
	h.jwksMu.Unlock()
	utility.Logger.Info().Msg("JWKS refreshed successfully")
	return nil
}

// jwtAudienceContains reports whether the "aud" claim in claims contains target.
// Per RFC 7519 §4.1.3, aud may be a single string or an array of strings.
func jwtAudienceContains(claims jwt.MapClaims, target string) bool {
	raw, ok := claims["aud"]
	if !ok {
		return false
	}
	switch v := raw.(type) {
	case string:
		return v == target
	case []any:
		for _, a := range v {
			if s, ok := a.(string); ok && s == target {
				return true
			}
		}
	}
	return false
}
