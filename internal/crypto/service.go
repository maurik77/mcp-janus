package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"mcpproxy/internal/config"
)

var (
	// ErrInvalidKey indicates key is invalid
	ErrInvalidKey = errors.New("invalid key")
	// ErrDecryptionFailed indicates decryption failed
	ErrDecryptionFailed = errors.New("decryption failed")
	// ErrKeyNotFound indicates key not found
	ErrKeyNotFound = errors.New("key not found")
)

// CryptoService handles AEAD encryption/decryption and key management
type CryptoService interface {
	// Encrypt encrypts plaintext using AEAD (AES-GCM)
	Encrypt(ctx context.Context, plaintext []byte, kid string) (ciphertext, nonce, tag []byte, err error)

	// Decrypt decrypts ciphertext using AEAD
	Decrypt(ctx context.Context, ciphertext, nonce, tag []byte, kid string) ([]byte, error)

	// GetCurrentKeyID returns the current active key ID
	GetCurrentKeyID(ctx context.Context) string

	// RotateKeys generates new encryption key and updates KID
	RotateKeys(ctx context.Context) error

	// GetKey retrieves key by KID (for decryption of old tokens)
	GetKey(ctx context.Context, kid string) ([]byte, error)
}

// AESGCMService implements CryptoService using AES-GCM
type AESGCMService struct {
	keyStore   KeyStore
	currentKID string
	mu         sync.RWMutex
}

// NewAESGCMService creates a new AES-GCM crypto service
func NewAESGCMService(cfg *config.Config) (*AESGCMService, error) {
	var keyStore KeyStore
	var err error

	switch cfg.KeyStoreType {
	case "memory":
		keyStore, err = NewMemoryKeyStore()
	case "file":
		keyStore, err = NewFileKeyStore(cfg.KeyStorePath)
	default:
		return nil, fmt.Errorf("unsupported key store type: %s", cfg.KeyStoreType)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create key store: %w", err)
	}

	service := &AESGCMService{
		keyStore: keyStore,
	}

	// Initialize with a key if none exists
	ctx := context.Background()
	keys, err := keyStore.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list keys: %w", err)
	}

	if len(keys) == 0 {
		// Generate initial key
		if err := service.RotateKeys(ctx); err != nil {
			return nil, fmt.Errorf("failed to generate initial key: %w", err)
		}
	} else {
		// Use existing current key
		kid, err := keyStore.GetCurrentKID(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to get current KID: %w", err)
		}
		service.currentKID = kid
	}

	return service, nil
}

// Encrypt encrypts plaintext using AES-GCM
func (s *AESGCMService) Encrypt(ctx context.Context, plaintext []byte, kid string) (ciphertext, nonce, tag []byte, err error) {
	key, err := s.keyStore.GetKey(ctx, kid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce = make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, nil, nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Seal returns ciphertext + tag concatenated
	sealed := gcm.Seal(nil, nonce, plaintext, nil)

	// Split ciphertext and tag
	tagSize := gcm.Overhead()
	if len(sealed) < tagSize {
		return nil, nil, nil, ErrDecryptionFailed
	}

	ciphertext = sealed[:len(sealed)-tagSize]
	tag = sealed[len(sealed)-tagSize:]

	return ciphertext, nonce, tag, nil
}

// Decrypt decrypts ciphertext using AES-GCM
func (s *AESGCMService) Decrypt(ctx context.Context, ciphertext, nonce, tag []byte, kid string) ([]byte, error) {
	key, err := s.keyStore.GetKey(ctx, kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Reconstruct sealed (ciphertext + tag)
	sealed := append(ciphertext, tag...)

	plaintext, err := gcm.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDecryptionFailed, err)
	}

	return plaintext, nil
}

// GetCurrentKeyID returns the current active key ID
func (s *AESGCMService) GetCurrentKeyID(ctx context.Context) string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.currentKID
}

// RotateKeys generates new encryption key and updates KID
func (s *AESGCMService) RotateKeys(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Generate new key (256-bit for AES-256)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return fmt.Errorf("failed to generate key: %w", err)
	}

	// Generate new KID (base64url encoded random bytes)
	kidBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, kidBytes); err != nil {
		return fmt.Errorf("failed to generate KID: %w", err)
	}
	kid := base64.URLEncoding.EncodeToString(kidBytes)
	kid = strings.TrimRight(kid, "=")

	// Store key
	if err := s.keyStore.StoreKey(ctx, kid, key); err != nil {
		return fmt.Errorf("failed to store key: %w", err)
	}

	// Set as current
	if err := s.keyStore.SetCurrentKID(ctx, kid); err != nil {
		return fmt.Errorf("failed to set current KID: %w", err)
	}

	s.currentKID = kid
	return nil
}

// GetKey retrieves key by KID
func (s *AESGCMService) GetKey(ctx context.Context, kid string) ([]byte, error) {
	return s.keyStore.GetKey(ctx, kid)
}
