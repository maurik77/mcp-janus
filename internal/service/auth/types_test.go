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

func TestClientIdData_Encode(t *testing.T) {
	tests := []struct {
		name    string
		data    *ClientIdData
		mockEnc utility.Encryption
		wantErr bool
		errMsg  string
	}{
		{
			name: "successful encoding",
			data: &ClientIdData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "test-secret-123",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encoding with multiple redirect URIs",
			data: &ClientIdData{
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
			data: &ClientIdData{
				RedirectURIs: []string{},
				Secret:       "empty-uris-secret",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encoding with nil redirect URIs",
			data: &ClientIdData{
				RedirectURIs: nil,
				Secret:       "nil-uris-secret",
			},
			mockEnc: &mockEncryption{},
			wantErr: false,
		},
		{
			name: "encryption fails",
			data: &ClientIdData{
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
		want      *ClientIdData
		wantErr   bool
		errMsg    string
	}{
		{
			name: "successful decoding",
			encrypted: func() string {
				data := &ClientIdData{
					RedirectURIs: []string{"https://example.com/callback"},
					Secret:       "test-secret-123",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &ClientIdData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "test-secret-123",
			},
			wantErr: false,
		},
		{
			name: "decoding with multiple redirect URIs",
			encrypted: func() string {
				data := &ClientIdData{
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
			want: &ClientIdData{
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
				data := &ClientIdData{
					RedirectURIs: []string{},
					Secret:       "",
				}
				dataJSON, _ := json.Marshal(data)
				return "encrypted_" + string(dataJSON)
			}(),
			mockEnc: &mockEncryption{},
			want: &ClientIdData{
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

func TestClientIdData_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		data *ClientIdData
	}{
		{
			name: "single redirect URI",
			data: &ClientIdData{
				RedirectURIs: []string{"https://example.com/callback"},
				Secret:       "secret-123",
			},
		},
		{
			name: "multiple redirect URIs",
			data: &ClientIdData{
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
			data: &ClientIdData{
				RedirectURIs: []string{},
				Secret:       "no-uris",
			},
		},
		{
			name: "special characters in secret",
			data: &ClientIdData{
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

// mockEncryptionError is a custom error type for testing
type mockEncryptionError struct {
	msg string
}

func (e *mockEncryptionError) Error() string {
	return e.msg
}
