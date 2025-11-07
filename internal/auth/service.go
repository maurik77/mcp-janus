package auth

import (
	"net/url"

	"golang.org/x/oauth2"
)

type Service interface {
	RegisterClient(req *RegisterRequest) (*RegisterResponse, error)
	OpenIDConfiguration() any
	ProtectedResourceMetadata() any
	AuthenticateRequest(req *AuthenticateRequest) (string, error)
	ManageAuthorizationCode(req *AuthorizationCodeData) (*AuthorizationCodeData, *url.URL, error)
	RetrieveAccessToken(req *AccessTokenRequest) (*oauth2.Token, error)
	RefreshToken(refreshToken string) (*oauth2.Token, error)
}
