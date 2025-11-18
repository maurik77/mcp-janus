package auth

import (
	"context"
	"encoding/hex"
	"fmt"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/utility"
	"net/url"
	"slices"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/oauth2"
)

type ProxyAuthHandler struct {
	config              config.Config
	encKey              [32]byte
	oauthConfig         *oauth2.Config
	encryption          utility.Encryption
	openidConfiguration *OpenIDConfiguration
	jwks                *JWKS
	tracer              trace.Tracer
}

func New(cfg config.Config, encryption utility.Encryption) (Service, error) {
	openidConfiguration, err := fetchOpenIDConfiguration(cfg.IDP.OpenIDConfigurationURL)
	if err != nil {
		return nil, err
	}

	jwks, err := fetchJWKS(openidConfiguration.JWKSEndpoint)
	if err != nil {
		return nil, err
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

	return &ProxyAuthHandler{
		config:              cfg,
		encKey:              cfg.EncryptionKey(),
		oauthConfig:         oauthConfig,
		encryption:          encryption,
		openidConfiguration: openidConfiguration,
		jwks:                jwks,
		tracer:              otel.Tracer("mcp-proxy.auth"),
	}, nil
}

func (s *ProxyAuthHandler) RegisterClient(req *RegisterRequest) (*RegisterResponse, error) {
	_, span := s.tracer.Start(context.Background(), "auth.RegisterClient")
	defer span.End()

	if req != nil && len(req.RedirectURIs) > 0 {
		span.SetAttributes(attribute.Int("redirect_uris.count", len(req.RedirectURIs)))
	}

	clientId, secret, err := generateClientID(req, s.encryption)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to generate client ID")
		return nil, err
	}

	span.SetAttributes(attribute.String("client.id", clientId))
	span.SetStatus(codes.Ok, "Client registered successfully")

	res := RegisterResponse{
		ClientID:     clientId,
		ClientSecret: secret,
	}

	return &res, nil
}

func (s *ProxyAuthHandler) AuthenticateRequest(req *AuthenticateRequest) (string, error) {
	_, span := s.tracer.Start(context.Background(), "auth.AuthenticateRequest")
	defer span.End()

	if req == nil || req.ClientID == "" {
		span.SetStatus(codes.Error, "Invalid request")
		return "", fmt.Errorf("invalid_request")
	}

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
		return "", fmt.Errorf("invalid_request")
	}

	// check redirect_uri is in clientData.RedirectURIs
	if !slices.Contains(clientData.RedirectURIs, req.RedirectURI) {
		span.SetStatus(codes.Error, "Invalid redirect URI")
		return "", fmt.Errorf("invalid_request")
	}

	stateData := StateData{
		OriginalState: req.State,
		RedirectURI:   req.RedirectURI,
	}

	// Redirect to real IdP
	authURL := s.oauthConfig.AuthCodeURL(
		stateData.Encode(),
		oauth2.SetAuthURLParam("code_challenge", req.CodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", req.CodeChallengeMethod),
		oauth2.SetAuthURLParam("redirect_uri", s.config.Proxy.BaseURL+"/callback"),
	)

	span.SetStatus(codes.Ok, "Authentication request successful")

	return authURL, nil
}

func (s *ProxyAuthHandler) ManageAuthorizationCode(req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error) {
	if req == nil {
		return nil, nil, fmt.Errorf("invalid_request")
	}
	// Decode state
	stateData, err := DecodeStateData(req.State)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid_request")
	}

	// Redirect back to client with original state and code
	redirectURL, err := url.Parse(stateData.RedirectURI)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid_request")
	}

	return &AuthorizationCodeData{
		State: stateData.OriginalState,
		Code:  req.Code,
	}, redirectURL, nil
}

func (s *ProxyAuthHandler) RetrieveAccessToken(req *AccessTokenRequest) (*oauth2.Token, error) {
	ctx, span := s.tracer.Start(context.Background(), "auth.RetrieveAccessToken")
	defer span.End()

	if req == nil {
		span.SetStatus(codes.Error, "Invalid request")
		return nil, fmt.Errorf("invalid_request")
	}

	if req.Code == "" || req.ClientID == "" {
		span.SetStatus(codes.Error, "Missing required parameters")
		return nil, fmt.Errorf("invalid_request")
	}

	span.SetAttributes(
		attribute.String("client.id", req.ClientID),
	)

	clientData, err := DecodeClientID(req.ClientID, s.encryption)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to decode client ID")
		return nil, err
	}

	if clientData.Secret != req.ClientSecret {
		span.SetStatus(codes.Error, "Invalid client secret")
		return nil, fmt.Errorf("invalid_request")
	}

	// Exchange with real IdP
	token, err := s.oauthConfig.Exchange(
		ctx,
		req.Code,
		oauth2.SetAuthURLParam("grant_type", req.GrantTypes),
		oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier),
	)

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Token exchange failed")
		return nil, fmt.Errorf("invalid_request")
	}

	span.AddEvent("Token received from IdP")

	opaqueToken := token
	opaqueToken.AccessToken, err = s.encryption.Encrypt([]byte(token.AccessToken))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt access token")
		return nil, err
	}

	opaqueToken.RefreshToken, err = s.encryption.Encrypt([]byte(token.RefreshToken))

	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "Failed to encrypt refresh token")
		return nil, err
	}

	span.SetStatus(codes.Ok, "Token exchange successful")
	return opaqueToken, err
}

func (s *ProxyAuthHandler) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	return &oauth2.Token{}, nil
}

func generateClientID(req *RegisterRequest, encryption utility.Encryption) (string, string, error) {
	// For simplicity, we only store redirect_uris in encrypted client_id
	// Generate a random secret (in real case, should be more robust)
	secretBytes := make([]byte, 16)
	for i := range secretBytes {
		secretBytes[i] = byte(65 + i) // Simple deterministic for example
	}
	clientSecret := hex.EncodeToString(secretBytes)

	clientData := ClientIdData{
		RedirectURIs: req.RedirectURIs,
		Secret:       clientSecret,
	}

	encryptedClientID, err := clientData.Encode(encryption)

	return encryptedClientID, clientSecret, err
}

func (s *ProxyAuthHandler) ValidateJWT(tokenString string) (*jwt.Token, error) {
	keyFunc := func(token *jwt.Token) (any, error) {
		if kid, ok := token.Header["kid"].(string); ok {
			if key := s.jwks.GetKeyByKID(kid); key != nil {
				return key, nil
			}
		}
		return nil, fmt.Errorf("key not found")
	}

	options := []jwt.ParserOption{}

	if s.config.IDP.JWTLeeway > 0 {
		options = append(options, jwt.WithLeeway(s.config.IDP.JWTLeeway))
	}

	token, err := jwt.Parse(tokenString, keyFunc, options...)
	if err != nil {
		return nil, err
	}

	return token, nil
}
