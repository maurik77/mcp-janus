package crypto

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// KeyStore manages encryption keys
type KeyStore interface {
	// GetKey retrieves a key by ID
	GetKey(ctx context.Context, kid string) ([]byte, error)

	// StoreKey stores a new key
	StoreKey(ctx context.Context, kid string, key []byte) error

	// ListKeys returns all key IDs
	ListKeys(ctx context.Context) ([]string, error)

	// GetCurrentKID returns the active key ID
	GetCurrentKID(ctx context.Context) (string, error)

	// SetCurrentKID sets the active key ID
	SetCurrentKID(ctx context.Context, kid string) error
}

// MemoryKeyStore is an in-memory implementation of KeyStore
type MemoryKeyStore struct {
	keys       map[string][]byte
	currentKID string
	mu         sync.RWMutex
}

// NewMemoryKeyStore creates a new in-memory key store
func NewMemoryKeyStore() (*MemoryKeyStore, error) {
	return &MemoryKeyStore{
		keys: make(map[string][]byte),
	}, nil
}

// GetKey retrieves a key by ID
func (s *MemoryKeyStore) GetKey(ctx context.Context, kid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	key, ok := s.keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Return a copy to prevent modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	return keyCopy, nil
}

// StoreKey stores a new key
func (s *MemoryKeyStore) StoreKey(ctx context.Context, kid string, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Store a copy to prevent external modification
	keyCopy := make([]byte, len(key))
	copy(keyCopy, key)
	s.keys[kid] = keyCopy
	return nil
}

// ListKeys returns all key IDs
func (s *MemoryKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	kids := make([]string, 0, len(s.keys))
	for kid := range s.keys {
		kids = append(kids, kid)
	}
	return kids, nil
}

// GetCurrentKID returns the active key ID
func (s *MemoryKeyStore) GetCurrentKID(ctx context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.currentKID == "" {
		return "", errors.New("no current key set")
	}
	return s.currentKID, nil
}

// SetCurrentKID sets the active key ID
func (s *MemoryKeyStore) SetCurrentKID(ctx context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.keys[kid]; !ok {
		return ErrKeyNotFound
	}

	s.currentKID = kid
	return nil
}

// FileKeyStore is a file-based implementation of KeyStore
type FileKeyStore struct {
	path string
	mu   sync.RWMutex
}

type fileKeyStoreData struct {
	Keys       map[string]string `json:"keys"` // kid -> base64 encoded key
	CurrentKID string            `json:"current_kid"`
}

// NewFileKeyStore creates a new file-based key store
func NewFileKeyStore(path string) (*FileKeyStore, error) {
	if path == "" {
		return nil, errors.New("key store path is required")
	}

	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key store directory: %w", err)
	}

	store := &FileKeyStore{path: path}

	// Initialize file if it doesn't exist
	if _, err := os.Stat(path); os.IsNotExist(err) {
		data := &fileKeyStoreData{
			Keys: make(map[string]string),
		}
		if err := store.save(data); err != nil {
			return nil, fmt.Errorf("failed to initialize key store: %w", err)
		}
	}

	return store, nil
}

// load reads the key store from disk
func (s *FileKeyStore) load() (*fileKeyStoreData, error) {
	content, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("failed to read key store: %w", err)
	}

	var data fileKeyStoreData
	if err := json.Unmarshal(content, &data); err != nil {
		return nil, fmt.Errorf("failed to parse key store: %w", err)
	}

	return &data, nil
}

// save writes the key store to disk
func (s *FileKeyStore) save(data *fileKeyStoreData) error {
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key store: %w", err)
	}

	// Write with restrictive permissions
	if err := os.WriteFile(s.path, content, 0600); err != nil {
		return fmt.Errorf("failed to write key store: %w", err)
	}

	return nil
}

// GetKey retrieves a key by ID
func (s *FileKeyStore) GetKey(ctx context.Context, kid string) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}

	keyStr, ok := data.Keys[kid]
	if !ok {
		return nil, ErrKeyNotFound
	}

	// Keys are stored as hex strings for readability
	key := []byte(keyStr)
	return key, nil
}

// StoreKey stores a new key
func (s *FileKeyStore) StoreKey(ctx context.Context, kid string, key []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return err
	}

	data.Keys[kid] = string(key)
	return s.save(data)
}

// ListKeys returns all key IDs
func (s *FileKeyStore) ListKeys(ctx context.Context) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.load()
	if err != nil {
		return nil, err
	}

	kids := make([]string, 0, len(data.Keys))
	for kid := range data.Keys {
		kids = append(kids, kid)
	}
	return kids, nil
}

// GetCurrentKID returns the active key ID
func (s *FileKeyStore) GetCurrentKID(ctx context.Context) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	data, err := s.load()
	if err != nil {
		return "", err
	}

	if data.CurrentKID == "" {
		return "", errors.New("no current key set")
	}
	return data.CurrentKID, nil
}

// SetCurrentKID sets the active key ID
func (s *FileKeyStore) SetCurrentKID(ctx context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	data, err := s.load()
	if err != nil {
		return err
	}

	if _, ok := data.Keys[kid]; !ok {
		return ErrKeyNotFound
	}

	data.CurrentKID = kid
	return s.save(data)
}
