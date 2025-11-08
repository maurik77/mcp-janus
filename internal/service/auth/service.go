package auth

import (
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"
)

type Service interface {
	RegisterClient(req *RegisterRequest) (*RegisterResponse, error)
	AuthenticateRequest(req *AuthenticateRequest) (string, error)
	ManageAuthorizationCode(req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error)
	RetrieveAccessToken(req *AccessTokenRequest) (*oauth2.Token, error)
	RefreshToken(refreshToken string) (*oauth2.Token, error)
	ValidateJWT(tokenString string) (*jwt.Token, error)
}
