package auth

import (
	"encoding/json"
	"mcpproxy/internal/utility"
	"testing"
)

// mockEncryption is a test implementation of utility.Encryption
type mockEncryption struct {
	encryptFunc func([]byte) (string, error)
	decryptFunc func(string) ([]byte, error)
}

func (m *mockEncryption) Encrypt(data []byte) (string, error) {
	if m.encryptFunc != nil {
		return m.encryptFunc(data)
	}
	return "encrypted_" + string(data), nil
}

func (m *mockEncryption) Decrypt(enc string) ([]byte, error) {
	if m.decryptFunc != nil {
		return m.decryptFunc(enc)
	}
	// Simple mock: strip the "encrypted_" prefix
	if len(enc) > 10 && enc[:10] == "encrypted_" {
		return []byte(enc[10:]), nil
	}
	return []byte(enc), nil
}

func TestClientIDData_Encode(t *testing.T) {
	tests := []struct {
		name    string
		data    *ClientIDData
		mockEnc utility.Encryption
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful encoding",
			data: &ClientIDData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "test-secret-123",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encoding with multiple redirect URIs",
			data: &ClientIDData{
				RedirectURIs: []string{
					"https://example.com/callback",
					"https://example.com/callback2",
				},
				Secret: "multi-secret",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encoding with empty redirect URIs",
			data: &ClientIDData{
				RedirectURIs: []string{},
				Secret:       "empty-uris-secret",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encoding with nil redirect URIs",
			data: &ClientIDData{
				RedirectURIs: nil,
				Secret:       "nil-uris-secret",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encryption fails",
			data: &ClientIDData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "test-secret",
			},
			mockEnc: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", &mockEncryptionError{"encryption failed"}
				},
			},
			wantErr: true,
			errMsg:  "encryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.data.Encode(tt.mockEnc)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Encode() expected error but got none")
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("Encode() error = %v, want %v", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("Encode() unexpected error = %v", err)
				return
			}

			if result == "" {
				t.Errorf("Encode() returned empty string")
			}
		})
	}
}

func TestDecodeClientID(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		mockEnc   utility.Encryption
		want      *ClientIDData
		wantErr   bool
		errMsg    string
	}{
		{
			name: "successful decoding",
			encrypted: func() string {
				data := &ClientIDData{
					RedirectURIs: []string{"https://example.com/callback"},
					Secret:       "test-secret-123",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &ClientIDData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "test-secret-123",
			},
			wantErr: false,
		},
		{
			name: "decoding with multiple redirect URIs",
			encrypted: func() string {
				data := &ClientIDData{
					RedirectURIs: []string{
						"https://example.com/callback",
						"https://example.com/callback2",
					},
					Secret: "multi-secret",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &ClientIDData{
				RedirectURIs: []string{
					"https://example.com/callback",
					"https://example.com/callback2",
				},
				Secret: "multi-secret",
			},
			wantErr: false,
		},
		{
			name:      "decryption fails",
			encrypted: "invalid-encrypted-data",
			mockEnc: &mockEncryption{
				decryptFunc: func(enc string) ([]byte, error) {
					return nil, &mockEncryptionError{"decryption failed"}
				},
			},
			want:    nil,
			wantErr: true,
			errMsg:  "decryption failed",
		},
		{
			name:      "invalid JSON after decryption",
			encrypted: "encrypted_invalid-json{{{",
			mockEnc:   &mockEncryption{},
			want:      nil,
			wantErr:   true,
		},
		{
			name: "empty encrypted string",
			encrypted: func() string {
				data := &ClientIDData{
					RedirectURIs: []string{},
					Secret:       "",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &ClientIDData{
				RedirectURIs: []string{},
				Secret:       "",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeClientID(tt.encrypted, tt.mockEnc)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DecodeClientID() expected error but got none")
					return
				}
				if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("DecodeClientID() error = %v, want %v", err.Error(), tt.errMsg)
				}
				return
			}

			if err != nil {
				t.Errorf("DecodeClientID() unexpected error = %v", err)
				return
			}

			if result == nil {
				t.Errorf("DecodeClientID() returned nil")
				return
			}

			// Compare the decoded data
			if result.Secret != tt.want.Secret {
				t.Errorf("DecodeClientID() Secret = %v, want %v", result.Secret, tt.want.Secret)
			}

			if len(result.RedirectURIs) != len(tt.want.RedirectURIs) {
				t.Errorf("DecodeClientID() RedirectURIs length = %v, want %v", len(result.RedirectURIs), len(tt.want.RedirectURIs))
				return
			}

			for i, uri := range result.RedirectURIs {
				if uri != tt.want.RedirectURIs[i] {
					t.Errorf("DecodeClientID() RedirectURIs[%d] = %v, want %v", i, uri, tt.want.RedirectURIs[i])
				}
			}
		})
	}
}

func TestClientIDData_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data *ClientIDData
	}{
		{
			name: "single redirect URI",
			data: &ClientIDData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "secret-123",
			},
		},
		{
			name: "multiple redirect URIs",
			data: &ClientIDData{
				RedirectURIs: []string{
					"https://example.com/callback",
					"https://example.com/callback2",
					"https://example.com/callback3",
				},
				Secret: "multi-uri-secret",
			},
		},
		{
			name: "empty redirect URIs",
			data: &ClientIDData{
				RedirectURIs: []string{},
				Secret:       "no-uris",
			},
		},
		{
			name: "special characters in secret",
			data: &ClientIDData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "secret!@#$%^&*()_+-=[]{}|;':\",./<>?",
			},
		},
	}

	mockEnc := &mockEncryption{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encode
			encoded, err := tt.data.Encode(mockEnc)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			// Decode
			decoded, err := DecodeClientID(encoded, mockEnc)
			if err != nil {
				t.Fatalf("DecodeClientID() error = %v", err)
			}

			// Verify round-trip
			if decoded.Secret != tt.data.Secret {
				t.Errorf("Round-trip Secret mismatch: got %v, want %v", decoded.Secret, tt.data.Secret)
			}

			if len(decoded.RedirectURIs) != len(tt.data.RedirectURIs) {
				t.Errorf("Round-trip RedirectURIs length mismatch: got %v, want %v", len(decoded.RedirectURIs), len(tt.data.RedirectURIs))
				return
			}

			for i, uri := range decoded.RedirectURIs {
				if uri != tt.data.RedirectURIs[i] {
					t.Errorf("Round-trip RedirectURIs[%d] mismatch: got %v, want %v", i, uri, tt.data.RedirectURIs[i])
				}
			}
		})
	}
}

func TestStateData_Encode(t *testing.T) {
	tests := []struct {
		name    string
		data    *StateData
		mockEnc utility.Encryption
		wantErr bool
	}{
		{
			name: "successful encoding",
			data: &StateData{
				OriginalState: "user-state-123",
				RedirectURI:   "https://client.example.com/callback",
				ClientID:      "encrypted-client-id",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encryption fails",
			data: &StateData{
				OriginalState: "state",
				RedirectURI:   "https://example.com/cb",
				ClientID:      "cid",
			},
			mockEnc: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", &mockEncryptionError{"encrypt failed"}
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.data.Encode(tt.mockEnc)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Encode() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("Encode() unexpected error = %v", err)
				return
			}
			if result == "" {
				t.Errorf("Encode() returned empty string")
			}
		})
	}
}

func TestDecodeStateData(t *testing.T) {
	tests := []struct {
		name      string
		encrypted string
		mockEnc   utility.Encryption
		want      *StateData
		wantErr   bool
	}{
		{
			name: "successful decoding",
			encrypted: func() string {
				data := &StateData{
					OriginalState: "user-state-abc",
					RedirectURI:   "https://client.example.com/callback",
					ClientID:      "enc-client-id",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &StateData{
				OriginalState: "user-state-abc",
				RedirectURI:   "https://client.example.com/callback",
				ClientID:      "enc-client-id",
			},
			wantErr: false,
		},
		{
			name:      "decryption fails",
			encrypted: "tampered-data",
			mockEnc: &mockEncryption{
				decryptFunc: func(enc string) ([]byte, error) {
					return nil, &mockEncryptionError{"decryption failed"}
				},
			},
			wantErr: true,
		},
		{
			name:      "invalid JSON after decryption",
			encrypted: "encrypted_not-json{{{",
			mockEnc:   &mockEncryption{},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := DecodeStateData(tt.encrypted, tt.mockEnc)
			if tt.wantErr {
				if err == nil {
					t.Errorf("DecodeStateData() expected error but got none")
				}
				return
			}
			if err != nil {
				t.Errorf("DecodeStateData() unexpected error = %v", err)
				return
			}
			if result.OriginalState != tt.want.OriginalState {
				t.Errorf("OriginalState = %v, want %v", result.OriginalState, tt.want.OriginalState)
			}
			if result.RedirectURI != tt.want.RedirectURI {
				t.Errorf("RedirectURI = %v, want %v", result.RedirectURI, tt.want.RedirectURI)
			}
			if result.ClientID != tt.want.ClientID {
				t.Errorf("ClientID = %v, want %v", result.ClientID, tt.want.ClientID)
			}
		})
	}
}

func TestStateData_RoundTrip(t *testing.T) {
	mockEnc := &mockEncryption{}

	tests := []struct {
		name string
		data *StateData
	}{
		{
			name: "basic round-trip",
			data: &StateData{
				OriginalState: "state-123",
				RedirectURI:   "https://example.com/callback",
				ClientID:      "enc-client-id-456",
			},
		},
		{
			name: "special characters",
			data: &StateData{
				OriginalState: "state=foo&bar=baz",
				RedirectURI:   "https://example.com/callback?param=value&other=1",
				ClientID:      "complex|client|id",
			},
		},
		{
			name: "empty original state",
			data: &StateData{
				OriginalState: "",
				RedirectURI:   "https://example.com/cb",
				ClientID:      "cid",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.data.Encode(mockEnc)
			if err != nil {
				t.Fatalf("Encode() error = %v", err)
			}

			decoded, err := DecodeStateData(encoded, mockEnc)
			if err != nil {
				t.Fatalf("DecodeStateData() error = %v", err)
			}

			if decoded.OriginalState != tt.data.OriginalState {
				t.Errorf("OriginalState mismatch: got %v, want %v", decoded.OriginalState, tt.data.OriginalState)
			}
			if decoded.RedirectURI != tt.data.RedirectURI {
				t.Errorf("RedirectURI mismatch: got %v, want %v", decoded.RedirectURI, tt.data.RedirectURI)
			}
			if decoded.ClientID != tt.data.ClientID {
				t.Errorf("ClientID mismatch: got %v, want %v", decoded.ClientID, tt.data.ClientID)
			}
		})
	}
}

func TestSelfIssuedTokenData_Encode(t *testing.T) {
	tests := []struct {
		name    string
		data    *SelfIssuedTokenData
		mockEnc utility.Encryption
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful encoding",
			data: &SelfIssuedTokenData{
				Type:      "si",
				IssuedAt:  1000,
				ExpiresAt: 2000,
				Claims:    map[string]string{"X-Sub": "user-123"},
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "empty claims",
			data: &SelfIssuedTokenData{
				Type:      "si",
				IssuedAt:  1000,
				ExpiresAt: 2000,
				Claims:    map[string]string{},
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encryption fails",
			data: &SelfIssuedTokenData{
				Type:      "si",
				IssuedAt:  1000,
				ExpiresAt: 2000,
				Claims:    map[string]string{"X-Sub": "user-123"},
			},
			mockEnc: &mockEncryption{
				encryptFunc: func(data []byte) (string, error) {
					return "", &mockEncryptionError{"encryption failed"}
				},
			},
			wantErr: true,
			errMsg:  "encryption failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := tt.data.Encode(tt.mockEnc)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result == "" {
				t.Error("expected non-empty encoded result")
			}
		})
	}
}

func TestDecodeSelfIssuedToken(t *testing.T) {
	tests := []struct {
		name      string
		buildEnc  func() (string, utility.Encryption)
		wantErr   bool
		errMsg    string
		checkData func(*testing.T, *SelfIssuedTokenData)
	}{
		{
			name: "successful decode",
			buildEnc: func() (string, utility.Encryption) {
				enc := &mockEncryption{}
				data := &SelfIssuedTokenData{
					Type:      "si",
					IssuedAt:  1000,
					ExpiresAt: 2000,
					Claims:    map[string]string{"X-Sub": "user-123", "X-Email": "a@b.com"},
				}
				encoded, _ := data.Encode(enc)
				return encoded, enc
			},
			wantErr: false,
			checkData: func(t *testing.T, si *SelfIssuedTokenData) {
				if si.Type != "si" {
					t.Errorf("Type: got %q want %q", si.Type, "si")
				}
				if si.IssuedAt != 1000 {
					t.Errorf("IssuedAt: got %d want 1000", si.IssuedAt)
				}
				if si.ExpiresAt != 2000 {
					t.Errorf("ExpiresAt: got %d want 2000", si.ExpiresAt)
				}
				if si.Claims["X-Sub"] != "user-123" {
					t.Errorf("Claims[X-Sub]: got %q want %q", si.Claims["X-Sub"], "user-123")
				}
			},
		},
		{
			name: "decryption fails",
			buildEnc: func() (string, utility.Encryption) {
				enc := &mockEncryption{
					decryptFunc: func(string) ([]byte, error) {
						return nil, &mockEncryptionError{"decrypt error"}
					},
				}
				return "any-value", enc
			},
			wantErr: true,
			errMsg:  "decrypt error",
		},
		{
			name: "wrong type discriminator",
			buildEnc: func() (string, utility.Encryption) {
				enc := &mockEncryption{}
				// Manually encode a blob with wrong type
				encoded := "encrypted_" + `{"t":"proxy","exp":2000,"iat":1000,"cl":{}}`
				return encoded, enc
			},
			wantErr: true,
			errMsg:  "not a self-issued token",
		},
		{
			name: "invalid JSON",
			buildEnc: func() (string, utility.Encryption) {
				enc := &mockEncryption{}
				return "encrypted_not-json-at-all", enc
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, enc := tt.buildEnc()
			result, err := DecodeSelfIssuedToken(encoded, enc)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && !containsString(err.Error(), tt.errMsg) {
					t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.checkData != nil {
				tt.checkData(t, result)
			}
		})
	}
}

func TestSelfIssuedTokenData_RoundTrip(t *testing.T) {
	enc := &mockEncryption{}
	original := &SelfIssuedTokenData{
		Type:      "si",
		IssuedAt:  1700000000,
		ExpiresAt: 1700086400,
		Claims: map[string]string{
			"X-Sub":   "user-abc",
			"X-Email": "user@example.com",
			"X-Tenant": "acme",
		},
	}

	encoded, err := original.Encode(enc)
	if err != nil {
		t.Fatalf("Encode() error: %v", err)
	}

	decoded, err := DecodeSelfIssuedToken(encoded, enc)
	if err != nil {
		t.Fatalf("DecodeSelfIssuedToken() error: %v", err)
	}

	if decoded.Type != original.Type {
		t.Errorf("Type mismatch: %q vs %q", decoded.Type, original.Type)
	}
	if decoded.IssuedAt != original.IssuedAt {
		t.Errorf("IssuedAt mismatch: %d vs %d", decoded.IssuedAt, original.IssuedAt)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt mismatch: %d vs %d", decoded.ExpiresAt, original.ExpiresAt)
	}
	for k, v := range original.Claims {
		if decoded.Claims[k] != v {
			t.Errorf("Claims[%s]: got %q want %q", k, decoded.Claims[k], v)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}())
}

// mockEncryptionError is a custom error type for testing
type mockEncryptionError struct {
	msg string
}

func (e *mockEncryptionError) Error() string {
	return e.msg
}
