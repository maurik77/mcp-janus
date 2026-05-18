package wire

import (
	"context"
	"mcpproxy/internal/infrastructure/telemetry"
	"mcpproxy/internal/service/auth"
	"net/http"
	"net/url"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/mock"
	"go.opentelemetry.io/otel/metric/noop"
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

func (m *MockMetadataService) AuthorizationServerMetadata() any {
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

// MockProxy implements server.Proxy for testing
type MockProxy struct {
	mock.Mock
}

func (m *MockProxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	m.Called(w, r)
}

func (m *MockProxy) AuthMiddleware() func(http.Handler) http.Handler {
	args := m.Called()
	return args.Get(0).(func(http.Handler) http.Handler)
}

// MockAuthService implements auth.Service for testing
type MockAuthService struct {
	mock.Mock
}

func (m *MockAuthService) RegisterClient(ctx context.Context, req *auth.RegisterRequest) (*auth.RegisterResponse, error) {
	args := m.Called(req)
	return args.Get(0).(*auth.RegisterResponse), args.Error(1)
}

func (m *MockAuthService) ValidateJWT(ctx context.Context, tokenString string) (*jwt.Token, error) {
	args := m.Called(tokenString)
	return args.Get(0).(*jwt.Token), args.Error(1)
}

func (m *MockAuthService) AuthenticateRequest(ctx context.Context, req *auth.AuthenticateRequest) (string, error) {
	args := m.Called(req)
	return args.String(0), args.Error(1)
}

func (m *MockAuthService) ManageAuthorizationCode(ctx context.Context, req *auth.AuthorizationCodeData) (*auth.AuthorizationCodeData, *url.URL, error) {
	args := m.Called(req)
	return args.Get(0).(*auth.AuthorizationCodeData), args.Get(1).(*url.URL), args.Error(2)
}

func (m *MockAuthService) RetrieveAccessToken(ctx context.Context, req *auth.AccessTokenRequest) (*oauth2.Token, error) {
	args := m.Called(req)
	return args.Get(0).(*oauth2.Token), args.Error(1)
}

func (m *MockAuthService) RefreshToken(ctx context.Context, refreshToken string) (*oauth2.Token, error) {
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

// createTestMetrics creates a no-op metrics instance for testing
func createTestMetrics() *telemetry.Metrics {
	meter := noop.NewMeterProvider().Meter("test")
	metrics, _ := telemetry.InitializeMetrics(meter)
	return metrics
}
