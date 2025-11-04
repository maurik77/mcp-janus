package tokens

import (
	"context"
	"testing"
	"time"

	"mcpproxy/internal/config"
	"mcpproxy/internal/crypto"
)

func TestOpaqueTokenService_CreateAndValidate(t *testing.T) {
	// Setup
	cfg := &config.Config{
		ProxyURL:       "https://proxy.example.com",
		OpaqueTokenTTL: 15 * time.Minute,
	}

	cryptoService, err := createTestCryptoService()
	if err != nil {
		t.Fatalf("failed to create crypto service: %v", err)
	}

	service := NewOpaqueTokenService(cryptoService, cfg)
	ctx := context.Background()

	tests := []struct {
		name    string
		payload *OpaqueTokenPayload
		wantErr bool
	}{
		{
			name: "valid payload",
			payload: &OpaqueTokenPayload{
				RTID:  "test-rtid-123",
				Scope: []string{"mcp:read", "mcp:write"},
			},
			wantErr: false,
		},
		{
			name: "empty payload with auto-generation",
			payload: &OpaqueTokenPayload{
				Scope: []string{"mcp:read"},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token
			token, err := service.Create(ctx, tt.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Create() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			if token == "" {
				t.Error("Create() returned empty token")
			}

			// Validate token
			validated, err := service.Validate(ctx, token)
			if err != nil {
				t.Errorf("Validate() error = %v", err)
				return
			}

			if validated.Aud != cfg.ProxyURL {
				t.Errorf("Validate() Aud = %v, want %v", validated.Aud, cfg.ProxyURL)
			}

			if validated.Ver != 1 {
				t.Errorf("Validate() Ver = %v, want 1", validated.Ver)
			}

			if validated.RTID == "" {
				t.Error("Validate() RTID is empty")
			}

			if validated.Exp == 0 {
				t.Error("Validate() Exp is zero")
			}

			if validated.IsExpired() {
				t.Error("Validate() token should not be expired")
			}
		})
	}
}

func TestOpaqueTokenService_ValidateExpiredToken(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:       "https://proxy.example.com",
		OpaqueTokenTTL: 15 * time.Minute,
	}

	cryptoService, err := createTestCryptoService()
	if err != nil {
		t.Fatalf("failed to create crypto service: %v", err)
	}

	service := NewOpaqueTokenService(cryptoService, cfg)
	ctx := context.Background()

	// Create token with past expiry
	payload := &OpaqueTokenPayload{
		RTID:  "test-rtid",
		Exp:   time.Now().Add(-1 * time.Hour).Unix(),
		Aud:   cfg.ProxyURL,
		Scope: []string{"mcp:read"},
		Ver:   1,
		KID:   cryptoService.GetCurrentKeyID(ctx),
	}

	token, err := service.Create(ctx, payload)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Validate should fail due to expiry
	_, err = service.Validate(ctx, token)
	if err != ErrTokenExpired {
		t.Errorf("Validate() expired token should return ErrTokenExpired, got %v", err)
	}
}

func TestOpaqueTokenService_ValidateInvalidAudience(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:       "https://proxy.example.com",
		OpaqueTokenTTL: 15 * time.Minute,
	}

	cryptoService, err := createTestCryptoService()
	if err != nil {
		t.Fatalf("failed to create crypto service: %v", err)
	}

	service := NewOpaqueTokenService(cryptoService, cfg)
	ctx := context.Background()

	// Create token with wrong audience
	payload := &OpaqueTokenPayload{
		RTID:  "test-rtid",
		Exp:   time.Now().Add(15 * time.Minute).Unix(),
		Aud:   "https://wrong-audience.example.com",
		Scope: []string{"mcp:read"},
		Ver:   1,
		KID:   cryptoService.GetCurrentKeyID(ctx),
	}

	token, err := service.Create(ctx, payload)
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Validate should fail due to audience mismatch
	_, err = service.Validate(ctx, token)
	if err != ErrInvalidAudience {
		t.Errorf("Validate() wrong audience should return ErrInvalidAudience, got %v", err)
	}
}

func TestOpaqueTokenService_ValidateInvalidFormat(t *testing.T) {
	cfg := &config.Config{
		ProxyURL:       "https://proxy.example.com",
		OpaqueTokenTTL: 15 * time.Minute,
	}

	cryptoService, err := createTestCryptoService()
	if err != nil {
		t.Fatalf("failed to create crypto service: %v", err)
	}

	service := NewOpaqueTokenService(cryptoService, cfg)
	ctx := context.Background()

	tests := []struct {
		name  string
		token string
	}{
		{
			name:  "empty token",
			token: "",
		},
		{
			name:  "invalid format - no dots",
			token: "invalidtoken",
		},
		{
			name:  "invalid format - only one dot",
			token: "part1.part2",
		},
		{
			name:  "invalid format - too many dots",
			token: "part1.part2.part3.part4",
		},
		{
			name:  "invalid base64",
			token: "!!!.!!!.!!!",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := service.Validate(ctx, tt.token)
			if err == nil {
				t.Error("Validate() should fail for invalid token format")
			}
		})
	}
}

func TestMemoryStore(t *testing.T) {
	cfg := &config.Config{}
	store, err := NewMemoryStore(cfg)
	if err != nil {
		t.Fatalf("NewMemoryStore() error = %v", err)
	}

	ctx := context.Background()

	// Store credentials
	creds := &UpstreamCredentials{
		RTID:         "test-rtid",
		AccessToken:  "test-access-token",
		RefreshToken: "test-refresh-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Scope:        "mcp:read mcp:write",
		ResourceURL:  "https://mcp.example.com",
	}

	if err := store.Store(ctx, creds.RTID, creds); err != nil {
		t.Fatalf("Store() error = %v", err)
	}

	// Retrieve credentials
	retrieved, err := store.Retrieve(ctx, creds.RTID)
	if err != nil {
		t.Fatalf("Retrieve() error = %v", err)
	}

	if retrieved.RTID != creds.RTID {
		t.Errorf("Retrieve() RTID = %v, want %v", retrieved.RTID, creds.RTID)
	}

	if retrieved.AccessToken != creds.AccessToken {
		t.Errorf("Retrieve() AccessToken = %v, want %v", retrieved.AccessToken, creds.AccessToken)
	}

	if retrieved.IsExpired() {
		t.Error("Retrieve() credentials should not be expired")
	}

	// Delete credentials
	if err := store.Delete(ctx, creds.RTID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}

	// Try to retrieve deleted credentials
	_, err = store.Retrieve(ctx, creds.RTID)
	if err != ErrTokenNotFound {
		t.Errorf("Retrieve() after Delete should return ErrTokenNotFound, got %v", err)
	}
}

func TestUpstreamCredentials_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		want      bool
	}{
		{
			name:      "not expired - 1 hour from now",
			expiresAt: time.Now().Add(1 * time.Hour),
			want:      false,
		},
		{
			name:      "not expired - 2 minutes from now",
			expiresAt: time.Now().Add(2 * time.Minute),
			want:      false,
		},
		{
			name:      "expired - 1 hour ago",
			expiresAt: time.Now().Add(-1 * time.Hour),
			want:      true,
		},
		{
			name:      "expired - within buffer (30 seconds)",
			expiresAt: time.Now().Add(30 * time.Second),
			want:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			creds := &UpstreamCredentials{
				ExpiresAt: tt.expiresAt,
			}

			if got := creds.IsExpired(); got != tt.want {
				t.Errorf("IsExpired() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to create a test crypto service
func createTestCryptoService() (crypto.CryptoService, error) {
	cfg := &config.Config{
		KeyStoreType: "memory",
	}

	return crypto.NewAESGCMService(cfg)
}
