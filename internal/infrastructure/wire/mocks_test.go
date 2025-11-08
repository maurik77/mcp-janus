package wire

import (
	"mcpproxy/internal/service/auth"
	"net/url"

	"github.com/stretchr/testify/mock"
	"golang.org/x/oauth2"
)

// MockMetadataService implements metadata.Service for testing
type MockMetadataService struct {
	mock.Mock
}

func (m *MockMetadataService) OpenIDConfiguration() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockMetadataService) ProtectedResourceMetadata() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockMetadataService) WWWAuthenticateHeader() string {
	args := m.Called()
	return args.String(0)
}

// MockAuthService implements auth.Service for testing
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) RegisterClient(req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	args := m.Called(req)
	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
}

func (m *MockAuthService) OpenIDConfiguration() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockAuthService) ProtectedResourceMetadata() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockAuthService) AuthenticateRequest(req *auth.AuthenticateRequest) (string, error) {
	args := m.Called(req)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ManageAuthorizationCode(req *auth.AuthorizationCodeData) (*auth.AuthorizationCodeData, *url.URL, error) {
	args := m.Called(req)
	return args.Get(0).(*auth.AuthorizationCodeData), args.Get(1).(*url.URL), args.Error(2)
}

func (m *MockAuthService) RetrieveAccessToken(req *auth.AccessTokenRequest) (*oauth2.Token, error) {
	args := m.Called(req)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockAuthService) RefreshToken(refreshToken string) (*oauth2.Token, error) {
	args := m.Called(refreshToken)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

// MockEncryption implements utility.Encryption for testing
type MockEncryption struct {
	mock.Mock
}

func (m *MockEncryption) Encrypt(data []byte) (string, error) {
	args := m.Called(data)
	return args.String(0), args.Error(1)
}

func (m *MockEncryption) Decrypt(encrypted string) ([]byte, error) {
	args := m.Called(encrypted)
	return args.Get(0).([]byte), args.Error(1)
}
