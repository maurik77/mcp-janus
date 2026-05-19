package utility

import (
	"encoding/base64"
	"mcpproxy/internal/infrastructure/config"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validConfig() *config.Config {
	return &config.Config{
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{
			MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		},
	}
}

func TestNewEncryption(t *testing.T) {
	t.Run("valid config", func(t *testing.T) {
		enc, err := NewEncryption(validConfig())
		require.NoError(t, err)
		assert.NotNil(t, enc)
	})

	t.Run("empty master key", func(t *testing.T) {
		cfg := &config.Config{}
		enc, err := NewEncryption(cfg)
		assert.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "encryption master_key is not configured")
	})

	t.Run("invalid hex master key", func(t *testing.T) {
		cfg := &config.Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "not-hex-at-all",
			},
		}
		enc, err := NewEncryption(cfg)
		assert.Error(t, err)
		assert.Nil(t, enc)
	})

	t.Run("wrong length master key", func(t *testing.T) {
		cfg := &config.Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef",
			},
		}
		enc, err := NewEncryption(cfg)
		assert.Error(t, err)
		assert.Nil(t, enc)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
	})
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	enc, err := NewEncryption(validConfig())
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"simple text", []byte("hello world")},
		{"empty data", []byte("")},
		{"binary data", []byte{0x00, 0xFF, 0x01, 0xFE}},
		{"long data", []byte("the quick brown fox jumps over the lazy dog the quick brown fox jumps over the lazy dog")},
		{"JSON payload", []byte(`{"access_token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"}`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := enc.Encrypt(tt.plaintext)
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)

			decrypted, err := enc.Decrypt(ciphertext)
			require.NoError(t, err)
			if len(tt.plaintext) == 0 {
				assert.Empty(t, decrypted)
			} else {
				assert.Equal(t, tt.plaintext, decrypted)
			}
		})
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	enc, err := NewEncryption(validConfig())
	require.NoError(t, err)

	plaintext := []byte("same input")
	ct1, err := enc.Encrypt(plaintext)
	require.NoError(t, err)
	ct2, err := enc.Encrypt(plaintext)
	require.NoError(t, err)

	assert.NotEqual(t, ct1, ct2, "two encryptions of the same plaintext must produce different ciphertexts due to random nonce")
}

func TestDecryptInvalidBase64(t *testing.T) {
	enc, err := NewEncryption(validConfig())
	require.NoError(t, err)

	_, err = enc.Decrypt("not-valid-base64!!!")
	assert.Error(t, err)
}

func TestDecryptShortCiphertext(t *testing.T) {
	enc, err := NewEncryption(validConfig())
	require.NoError(t, err)

	// Encode fewer bytes than the nonce size (12 bytes for GCM)
	short := base64.URLEncoding.EncodeToString([]byte("short"))
	_, err = enc.Decrypt(short)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestDecryptTamperedCiphertext(t *testing.T) {
	enc, err := NewEncryption(validConfig())
	require.NoError(t, err)

	ciphertext, err := enc.Encrypt([]byte("sensitive data"))
	require.NoError(t, err)

	// Decode, flip a byte, re-encode
	raw, err := base64.URLEncoding.DecodeString(ciphertext)
	require.NoError(t, err)

	raw[len(raw)-1] ^= 0xFF
	tampered := base64.URLEncoding.EncodeToString(raw)

	_, err = enc.Decrypt(tampered)
	assert.Error(t, err, "decrypting tampered ciphertext must fail GCM authentication")
}

func TestDecryptWrongKey(t *testing.T) {
	enc1, err := NewEncryption(validConfig())
	require.NoError(t, err)

	cfg2 := &config.Config{
		Encryption: struct {
			MasterKey string `mapstructure:"master_key"`
		}{
			MasterKey: "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd",
		},
	}
	enc2, err := NewEncryption(cfg2)
	require.NoError(t, err)

	ciphertext, err := enc1.Encrypt([]byte("secret"))
	require.NoError(t, err)

	_, err = enc2.Decrypt(ciphertext)
	assert.Error(t, err, "decrypting with a different key must fail")
}
