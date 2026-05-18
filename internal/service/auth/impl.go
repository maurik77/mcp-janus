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

type ProxyAuthHandler struct {
	config              config.Config
	oauthConfig         *oauth2.Config
	encryption          utility.Encryption
	openidConfiguration *OpenIDConfiguration
	jwks                *JWKS
	jwksMu              sync.RWMutex
	tracer              trace.Tracer
	httpClient          *http.Client
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
	}
	utility.Logger.Info().
		Str("issuer", openidConfiguration.Issuer).
		Int("jwks_keys", len(jwks.Keys)).
		Msg("Auth service initialized")
	utility.Logger.Debug().
		Str("idp_client_id", cfg.IDP.ClientID).
		Str("idp_client_secret", cfg.IDP.ClientSecret).
		Str("redirect_url", cfg.Proxy.BaseURL+"/callback").
		Str("auth_url", openidConfiguration.AuthorizationEndpoint).
		Str("token_url", openidConfiguration.TokenEndpoint).
		Strs("scopes", cfg.IDP.Scopes).
		Msg("[DEBUG] New: oauth config")
	return handler, nil
}

func (s *ProxyAuthHandler) RegisterClient(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error) {
	_, span := s.tracer.Start(ctx, "auth.RegisterClient")
	defer span.End()

	utility.Logger.Debug().
		Str("client_name", req.ClientName).
		Strs("redirect_uris", req.RedirectURIs).
		Strs("grant_types", req.GrantTypes).
		Strs("response_types", req.ResponseTypes).
		Str("token_endpoint_auth_method", req.TokenEndpointAuthMethod).
		Msg("[DEBUG] RegisterClient: request received")

	if req != nil && len(req.RedirectURIs) > 0 {
		span.SetAttributes(attribute.Int("redirect_uris.count", len(req.RedirectURIs)))
	}

	clientId, secret, err := generateClientID(req, s.encryption)

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
		Str("client_secret", secret).
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

func (s *ProxyAuthHandler) AuthenticateRequest(ctx context.Context, req *AuthenticateRequest) (string, error) {
	_, span := s.tracer.Start(ctx, "auth.AuthenticateRequest")
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

	clientData, err := DecodeClientID(req.ClientID, s.encryption)

	// Decrypt client_id to get redirect_uri
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode client ID")
		utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("AuthenticateRequest: failed to decode client_id")
		return "", fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Strs("registered_redirect_uris", clientData.RedirectURIs).
		Str("requested_redirect_uri", req.RedirectURI).
		Msg("[DEBUG] AuthenticateRequest: decoded client data")

	// check redirect_uri is in clientData.RedirectURIs
	if !slices.Contains(clientData.RedirectURIs, req.RedirectURI) {
		span.SetStatus(codes.Error, "Invalid redirect URI")
		utility.Logger.Warn().
			Str("client_id", req.ClientID).
			Str("redirect_uri", req.RedirectURI).
			Msg("AuthenticateRequest: redirect_uri not registered for client")
		return "", fmt.Errorf("invalid_request")
	}

	stateData := StateData{
		OriginalState: req.State,
		RedirectURI:   req.RedirectURI,
		ClientID:      req.ClientID,
	}

	encryptedState, err := stateData.Encode(s.encryption)
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
	authURL := s.oauthConfig.AuthCodeURL(
		encryptedState,
		oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", req.CodeChallengeMethod),
		oauth2.SetAuthURLParam("redirect_uri", s.config.Proxy.BaseURL+"/callback"),
	)

	span.SetStatus(codes.Ok, "Authentication request successful")

	utility.Logger.Info().Str("auth_url", authURL).Msg("Authentication request successful")

	return authURL, nil
}

func (s *ProxyAuthHandler) ManageAuthorizationCode(ctx context.Context, req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error) {
	if req == nil {
		utility.Logger.Warn().Msg("ManageAuthorizationCode: nil request")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("code", req.Code).
		Str("encrypted_state", req.State).
		Msg("[DEBUG] ManageAuthorizationCode: request received")
	// Decrypt and decode state
	stateData, err := DecodeStateData(req.State, s.encryption)
	if err != nil {
		utility.Logger.Warn().Err(err).Msg("ManageAuthorizationCode: failed to decode state")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("original_state", stateData.OriginalState).
		Str("client_id", stateData.ClientID).
		Str("redirect_uri", stateData.RedirectURI).
		Msg("[DEBUG] ManageAuthorizationCode: decoded state")

	// Validate redirect URI against registered client
	clientData, err := DecodeClientID(stateData.ClientID, s.encryption)
	if err != nil {
		utility.Logger.Warn().Err(err).Str("client_id", stateData.ClientID).Msg("ManageAuthorizationCode: failed to decode client_id")
		return nil, nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Strs("registered_redirect_uris", clientData.RedirectURIs).
		Str("state_redirect_uri", stateData.RedirectURI).
		Msg("[DEBUG] ManageAuthorizationCode: decoded client data")

	if !slices.Contains(clientData.RedirectURIs, stateData.RedirectURI) {
		utility.Logger.Warn().
			Str("client_id", stateData.ClientID).
			Str("redirect_uri", stateData.RedirectURI).
			Msg("ManageAuthorizationCode: redirect_uri not registered for client")
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

	utility.Logger.Info().
		Str("client_id", stateData.ClientID).
		Str("redirect_uri", redirectURL.String()).
		Msg("Authorization code dispatched to client")

	return res, redirectURL, nil
}

func (s *ProxyAuthHandler) RetrieveAccessToken(ctx context.Context, req *AccessTokenRequest) (*oauth2.Token, error) {
	ctx, span := s.tracer.Start(ctx, "auth.RetrieveAccessToken")
	defer span.End()

	if req == nil {
		span.SetStatus(codes.Error, "Invalid request")
		utility.Logger.Warn().Msg("RetrieveAccessToken: nil request")
		return nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("client_id", req.ClientID).
		Str("client_secret", req.ClientSecret).
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
		span.SetAttributes(
			attribute.String("client.id", req.ClientID),
		)

		clientData, err := DecodeClientID(req.ClientID, s.encryption)

		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to decode client ID")
			utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: failed to decode client_id")
			return nil, err
		}

		utility.Logger.Debug().
			Str("client_id", req.ClientID).
			Str("stored_secret", clientData.Secret).
			Str("provided_secret", req.ClientSecret).
			Bool("match", clientData.Secret == req.ClientSecret).
			Msg("[DEBUG] RetrieveAccessToken: client secret comparison")

		// Only validate secret when the client provided one (confidential clients).
		// Public clients (token_endpoint_auth_method=none) rely on PKCE instead.
		if req.ClientSecret != "" && clientData.Secret != req.ClientSecret {
			span.SetStatus(codes.Error, "Invalid client secret")
			utility.Logger.Warn().Str("client_id", req.ClientID).Msg("RetrieveAccessToken: client secret mismatch")
			return nil, fmt.Errorf("invalid_request")
		}
	}

	// Exchange with real IdP
	httpClient := s.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	token, err := s.oauthConfig.Exchange(
		oauthCtx,
		req.Code,
		oauth2.SetAuthURLParam("grant_type", req.GrantTypes),
		oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Token exchange failed")
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: token exchange with IdP failed")
		return nil, fmt.Errorf("invalid_request")
	}

	span.AddEvent("Token received from IdP")

	opaqueToken := token
	opaqueToken.AccessToken, err = s.encryption.Encrypt([]byte(token.AccessToken))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt access token")
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: failed to encrypt access token")
		return nil, err
	}

	opaqueToken.RefreshToken, err = s.encryption.Encrypt([]byte(token.RefreshToken))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt refresh token")
		utility.Logger.Error().Err(err).Str("client_id", req.ClientID).Msg("RetrieveAccessToken: failed to encrypt refresh token")
		return nil, err
	}

	span.SetStatus(codes.Ok, "Token exchange successful")

	utility.Logger.Info().
		Str("client_id", req.ClientID).
		Str("token_type", opaqueToken.TokenType).
		Time("expiry", opaqueToken.Expiry).
		Msg("Access token issued to client")

	return opaqueToken, err
}

func (s *ProxyAuthHandler) RefreshToken(ctx context.Context, req *RefreshTokenRequest) (*oauth2.Token, error) {
	ctx, span := s.tracer.Start(ctx, "auth.RefreshToken")
	defer span.End()

	if req == nil {
		span.SetStatus(codes.Error, "Invalid request")
		utility.Logger.Warn().Msg("RefreshToken: nil request")
		return nil, fmt.Errorf("invalid_request")
	}

	utility.Logger.Debug().
		Str("grant_type", req.GrantType).
		Str("client_id", req.ClientID).
		Str("client_secret", req.ClientSecret).
		Str("encrypted_refresh_token", req.RefreshToken).
		Msg("[DEBUG] RefreshToken: request received")

	if req.RefreshToken == "" {
		span.SetStatus(codes.Error, "Missing refresh token")
		utility.Logger.Warn().Msg("RefreshToken: empty refresh token")
		return nil, fmt.Errorf("invalid_request")
	}

	if req.ClientID != "" {
		clientData, err := DecodeClientID(req.ClientID, s.encryption)
		if err != nil {
			span.RecordError(err)
			span.SetStatus(codes.Error, "Failed to decode client ID")
			utility.Logger.Warn().Err(err).Str("client_id", req.ClientID).Msg("RefreshToken: failed to decode client_id")
			return nil, fmt.Errorf("invalid_request")
		}
		utility.Logger.Debug().
			Str("client_id", req.ClientID).
			Str("stored_secret", clientData.Secret).
			Str("provided_secret", req.ClientSecret).
			Bool("match", clientData.Secret == req.ClientSecret).
			Msg("[DEBUG] RefreshToken: client secret comparison")
		if req.ClientSecret != "" && clientData.Secret != req.ClientSecret {
			span.SetStatus(codes.Error, "Invalid client secret")
			utility.Logger.Warn().Str("client_id", req.ClientID).Msg("RefreshToken: client secret mismatch")
			return nil, fmt.Errorf("invalid_request")
		}
	}

	decryptedRefreshToken, err := s.encryption.Decrypt(req.RefreshToken)
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

	httpClient := s.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	oauthCtx := context.WithValue(ctx, oauth2.HTTPClient, httpClient)
	tokenSource := s.oauthConfig.TokenSource(oauthCtx, &oauth2.Token{
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

	opaqueToken := token
	opaqueToken.AccessToken, err = s.encryption.Encrypt([]byte(token.AccessToken))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt access token")
		utility.Logger.Error().Err(err).Msg("RefreshToken: failed to encrypt access token")
		return nil, err
	}

	opaqueToken.RefreshToken, err = s.encryption.Encrypt([]byte(token.RefreshToken))
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt refresh token")
		utility.Logger.Error().Err(err).Msg("RefreshToken: failed to encrypt refresh token")
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
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		return "", "", fmt.Errorf("failed to generate client secret: %w", err)
	}
	clientSecret := hex.EncodeToString(secretBytes)

	clientData := ClientIdData{
		RedirectURIs: req.RedirectURIs,
		Secret:       clientSecret,
	}

	utility.Logger.Debug().
		Strs("redirect_uris", clientData.RedirectURIs).
		Str("secret", clientData.Secret).
		Msg("[DEBUG] generateClientID: client data before encoding")

	encryptedClientID, err := clientData.Encode(encryption)

	utility.Logger.Debug().
		Str("encrypted_client_id", encryptedClientID).
		Msg("[DEBUG] generateClientID: encrypted client_id")

	return encryptedClientID, clientSecret, err
}

func (s *ProxyAuthHandler) ValidateJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
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
		s.jwksMu.RLock()
		key := s.jwks.GetKeyByKID(kid)
		s.jwksMu.RUnlock()
		if key != nil {
			utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key found in cache")
			return key, nil
		}

		utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key not in cache, refreshing JWKS")

		// Cache miss — IdP may have rotated keys; refresh JWKS
		if err := s.refreshJWKS(); err != nil {
			utility.Logger.Warn().Err(err).Str("kid", kid).Msg("Failed to refresh JWKS")
			return nil, fmt.Errorf("key not found and JWKS refresh failed: %w", err)
		}

		s.jwksMu.RLock()
		key = s.jwks.GetKeyByKID(kid)
		s.jwksMu.RUnlock()
		if key != nil {
			utility.Logger.Debug().Str("kid", kid).Msg("[DEBUG] ValidateJWT: key found after JWKS refresh")
			return key, nil
		}

		return nil, fmt.Errorf("key %q not found after JWKS refresh", kid)
	}

	options := []jwt.ParserOption{}

	if s.config.IDP.JWTLeeway > 0 {
		options = append(options, jwt.WithLeeway(s.config.IDP.JWTLeeway))
	}

	utility.Logger.Debug().
		Dur("leeway", s.config.IDP.JWTLeeway).
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

// refreshJWKS re-fetches the JWKS from the IdP.
func (s *ProxyAuthHandler) refreshJWKS() error {
	jwks, err := fetchJWKS(s.openidConfiguration.JWKSEndpoint, s.config.IDP.SkipTLSVerify)
	if err != nil {
		return err
	}
	s.jwksMu.Lock()
	s.jwks = jwks
	s.jwksMu.Unlock()
	utility.Logger.Info().Msg("JWKS refreshed successfully")
	return nil
}
