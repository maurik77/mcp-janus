package auth

import (
	"context"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type Service interface {
	RegisterClient(ctx context.Context, req *RegisterRequest) (*RegisterResponse, error)
	AuthenticateRequest(ctx context.Context, req *AuthenticateRequest) (string, error)
	ManageAuthorizationCode(ctx context.Context, req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error)
	RetrieveAccessToken(ctx context.Context, req *AccessTokenRequest) (*oauth2.Token, error)
	RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error)
	ValidateJWT(ctx context.Context, tokenString string) (*jwt.Token, error)
}
