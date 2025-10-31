package crypto
package crypto

import (
	"context"
	"testing"
)

func TestAESGCMService_EncryptDecrypt(t *testing.T) {
	// Create in-memory key store
	keyStore, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	service := &AESGCMService{
		keyStore: keyStore,
	}

	ctx := context.Background()

	// Generate initial key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid := service.GetCurrentKeyID(ctx)

	tests := []struct {
		name      string
		plaintext string
	}{
		{
			name:      "simple text",
			plaintext: "Hello, World!",
		},
		{
			name:      "json payload",
			plaintext: `{"rtid":"abc123","exp":1234567890}`,
		},
		{
			name:      "empty string",
			plaintext: "",
		},
		{
			name:      "long text",
			plaintext: string(make([]byte, 10000)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Encrypt
			ciphertext, nonce, tag, err := service.Encrypt(ctx, []byte(tt.plaintext), kid)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if len(ciphertext) == 0 && len(tt.plaintext) > 0 {
				t.Error("ciphertext is empty for non-empty plaintext")
			}

			if len(nonce) == 0 {
				t.Error("nonce is empty")
			}

			if len(tag) == 0 {
				t.Error("tag is empty")
			}

			// Decrypt
			decrypted, err := service.Decrypt(ctx, ciphertext, nonce, tag, kid)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if string(decrypted) != tt.plaintext {
				t.Errorf("Decrypt() = %v, want %v", string(decrypted), tt.plaintext)
			}
		})
	}
}

func TestAESGCMService_DecryptWithWrongKey(t *testing.T) {
	keyStore, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	service := &AESGCMService{
		keyStore: keyStore,
	}

	ctx := context.Background()

	// Generate first key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid1 := service.GetCurrentKeyID(ctx)
	plaintext := []byte("secret message")

	// Encrypt with first key
	ciphertext, nonce, tag, err := service.Encrypt(ctx, plaintext, kid1)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Generate second key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid2 := service.GetCurrentKeyID(ctx)

	// Try to decrypt with second key (should fail)
	_, err = service.Decrypt(ctx, ciphertext, nonce, tag, kid2)
	if err == nil {
		t.Error("Decrypt() with wrong key should fail")
	}

	// Decrypt with original key (should succeed)
	decrypted, err := service.Decrypt(ctx, ciphertext, nonce, tag, kid1)
	if err != nil {
		t.Fatalf("Decrypt() with correct key error = %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("Decrypt() = %v, want %v", string(decrypted), string(plaintext))
	}
}

func TestAESGCMService_KeyRotation(t *testing.T) {
	keyStore, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	service := &AESGCMService{
		keyStore: keyStore,
	}

	ctx := context.Background()

	// Generate first key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid1 := service.GetCurrentKeyID(ctx)

	// Generate second key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid2 := service.GetCurrentKeyID(ctx)

	if kid1 == kid2 {
		t.Error("Key rotation should generate different KIDs")
	}

	// Both keys should exist
	key1, err := service.GetKey(ctx, kid1)
	if err != nil {
		t.Errorf("GetKey(kid1) error = %v", err)
	}

	key2, err := service.GetKey(ctx, kid2)
	if err != nil {
		t.Errorf("GetKey(kid2) error = %v", err)
	}

	if string(key1) == string(key2) {
		t.Error("Different KIDs should have different keys")
	}
}

func TestMemoryKeyStore(t *testing.T) {
	keyStore, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("NewMemoryKeyStore() error = %v", err)
	}

	ctx := context.Background()

	// Initially empty
	keys, err := keyStore.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("ListKeys() initially should be empty, got %d keys", len(keys))
	}

	// Store a key
	kid := "test-kid"
	key := []byte("test-key-32-bytes-long-enough!!")

	if err := keyStore.StoreKey(ctx, kid, key); err != nil {
		t.Fatalf("StoreKey() error = %v", err)
	}

	// Retrieve key
	retrievedKey, err := keyStore.GetKey(ctx, kid)
	if err != nil {
		t.Fatalf("GetKey() error = %v", err)
	}

	if string(retrievedKey) != string(key) {
		t.Errorf("GetKey() = %v, want %v", string(retrievedKey), string(key))
	}

	// List keys
	keys, err = keyStore.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	if len(keys) != 1 {
		t.Errorf("ListKeys() should have 1 key, got %d", len(keys))
	}

	// Set current KID
	if err := keyStore.SetCurrentKID(ctx, kid); err != nil {
		t.Fatalf("SetCurrentKID() error = %v", err)
	}

	// Get current KID
	currentKID, err := keyStore.GetCurrentKID(ctx)
	if err != nil {
		t.Fatalf("GetCurrentKID() error = %v", err)
	}

	if currentKID != kid {
		t.Errorf("GetCurrentKID() = %v, want %v", currentKID, kid)
	}

	// Try to get non-existent key
	_, err = keyStore.GetKey(ctx, "non-existent")
	if err != ErrKeyNotFound {
		t.Errorf("GetKey(non-existent) should return ErrKeyNotFound, got %v", err)
	}
}

func TestAESGCMService_DecryptTamperedCiphertext(t *testing.T) {
	keyStore, err := NewMemoryKeyStore()
	if err != nil {
		t.Fatalf("failed to create key store: %v", err)
	}

	service := &AESGCMService{
		keyStore: keyStore,
	}

	ctx := context.Background()

	// Generate key
	if err := service.RotateKeys(ctx); err != nil {
		t.Fatalf("failed to rotate keys: %v", err)
	}

	kid := service.GetCurrentKeyID(ctx)
	plaintext := []byte("secret message")

	// Encrypt
	ciphertext, nonce, tag, err := service.Encrypt(ctx, plaintext, kid)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Tamper with ciphertext
	if len(ciphertext) > 0 {
		ciphertext[0] ^= 0xFF
	}

	// Try to decrypt tampered ciphertext (should fail)
	_, err = service.Decrypt(ctx, ciphertext, nonce, tag, kid)
	if err == nil {
		t.Error("Decrypt() with tampered ciphertext should fail")
	}
}
