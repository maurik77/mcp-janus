// internal/auth/encryption.go
package utility

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"mcpproxy/internal/infrastructure/config"
)

type Encryption interface {
	Encrypt(data []byte) (string, error)
	Decrypt(enc string) ([]byte, error)
}

type encryption struct {
	cfg *config.Config
	key [32]byte
	gcm cipher.AEAD
}

func NewEncryption(cfg *config.Config) (Encryption, error) {
	key, err := cfg.EncryptionKey()
	if err != nil {
		return nil, fmt.Errorf("invalid encryption key: %w", err)
	}
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &encryption{
		cfg: cfg,
		key: key,
		gcm: gcm,
	}, nil
}

func (e *encryption) Encrypt(data []byte) (string, error) {
	nonce := make([]byte, e.gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := e.gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func (e *encryption) Decrypt(enc string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	nonceSize := e.gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	return e.gcm.Open(nil, nonce, cipherText, nil)
}
