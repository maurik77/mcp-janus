// internal/auth/encryption.go
package utility

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
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
}

func NewEncryption(cfg *config.Config) (Encryption, error) {
	return &encryption{
		cfg: cfg,
		key: cfg.EncryptionKey(),
	}, nil
}

func (e *encryption) Encrypt(data []byte) (string, error) {
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	cipherText := gcm.Seal(nonce, nonce, data, nil)
	return base64.URLEncoding.EncodeToString(cipherText), nil
}

func (e *encryption) Decrypt(enc string) ([]byte, error) {
	data, err := base64.URLEncoding.DecodeString(enc)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(e.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	return gcm.Open(nil, nonce, cipherText, nil)
}
