package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptionKey(t *testing.T) {
	t.Run("valid 32-byte key", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		}
		key, err := cfg.EncryptionKey()
		require.NoError(t, err)
		assert.Equal(t, byte(0x01), key[0])
		assert.Equal(t, byte(0x23), key[1])
	})

	t.Run("nil config", func(t *testing.T) {
		var cfg *Config
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("empty master key", func(t *testing.T) {
		cfg := &Config{}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not configured")
	})

	t.Run("invalid hex characters", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "not valid hex")
	})

	t.Run("too short", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
		assert.Contains(t, err.Error(), "got 8 bytes")
	})

	t.Run("too long", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef00",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "must be exactly 32 bytes")
		assert.Contains(t, err.Error(), "got 33 bytes")
	})

	t.Run("odd number of hex chars", func(t *testing.T) {
		cfg := &Config{
			Encryption: struct {
				MasterKey string `mapstructure:"master_key"`
			}{
				MasterKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
			},
		}
		_, err := cfg.EncryptionKey()
		assert.Error(t, err)
	})
}
