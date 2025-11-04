package tokens

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"mcpproxy/internal/config"
	"mcpproxy/internal/crypto"
)

var (
	// ErrInvalidToken indicates token format is invalid
	ErrInvalidToken = errors.New("invalid token format")
	// ErrInvalidAudience indicates audience mismatch
	ErrInvalidAudience = errors.New("invalid audience")
)

// OpaqueTokenService creates and validates opaque bearer tokens
type OpaqueTokenService interface {
	// Create generates an opaque token from payload
	Create(ctx context.Context, payload *OpaqueTokenPayload) (string, error)

	// Validate decrypts and validates an opaque token
	Validate(ctx context.Context, token string) (*OpaqueTokenPayload, error)
}

// OpaqueTokenPayload is the plaintext content before encryption
type OpaqueTokenPayload struct {
	RTID         string   `json:"rtid"`          // Reference to upstream credentials
	Exp          int64    `json:"exp"`           // Expiry timestamp
	Aud          string   `json:"aud"`           // Audience (this proxy URL)
	Scope        []string `json:"scp"`           // Scopes
	Ver          int      `json:"ver"`           // Token format version
	KID          string   `json:"kid"`           // Key ID for rotation
	AccessToken  string   `json:"access_token"`  // Encrypted real access token
	RefreshToken string   `json:"refresh_token"` // Encrypted real refresh token
}

// IsExpired checks if token is expired
func (p *OpaqueTokenPayload) IsExpired() bool {
	return time.Now().Unix() > p.Exp
}

// opaqueTokenServiceImpl implements OpaqueTokenService
type opaqueTokenServiceImpl struct {
	cryptoService crypto.CryptoService
	cfg           *config.Config
}

// NewOpaqueTokenService creates a new opaque token service
func NewOpaqueTokenService(cryptoService crypto.CryptoService, cfg *config.Config) OpaqueTokenService {
	return &opaqueTokenServiceImpl{
		cryptoService: cryptoService,
		cfg:           cfg,
	}
}

// Create generates an opaque token from payload
func (s *opaqueTokenServiceImpl) Create(ctx context.Context, payload *OpaqueTokenPayload) (string, error) {
	// Set expiry if not already set
	if payload.Exp == 0 {
		payload.Exp = time.Now().Add(s.cfg.OpaqueTokenTTL).Unix()
	}

	// Set audience if not already set
	if payload.Aud == "" {
		payload.Aud = s.cfg.ProxyURL
	}

	// Set version
	payload.Ver = 1

	// Get current KID if not set
	if payload.KID == "" {
		payload.KID = s.cryptoService.GetCurrentKeyID(ctx)
	}

	// Generate RTID if not set
	if payload.RTID == "" {
		rtidBytes := make([]byte, 16)
		if _, err := io.ReadFull(rand.Reader, rtidBytes); err != nil {
			return "", fmt.Errorf("failed to generate RTID: %w", err)
		}
		payload.RTID = base64.URLEncoding.EncodeToString(rtidBytes)
		payload.RTID = strings.TrimRight(payload.RTID, "=")
	}

	// Encrypt real access token if provided
	if payload.AccessToken != "" {
		encryptedAccessToken, err := s.encryptToken(ctx, payload.AccessToken, payload.KID)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt access token: %w", err)
		}
		payload.AccessToken = encryptedAccessToken
	}

	// Encrypt real refresh token if provided
	if payload.RefreshToken != "" {
		encryptedRefreshToken, err := s.encryptToken(ctx, payload.RefreshToken, payload.KID)
		if err != nil {
			return "", fmt.Errorf("failed to encrypt refresh token: %w", err)
		}
		payload.RefreshToken = encryptedRefreshToken
	}

	// Marshal payload to JSON
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	// Encrypt using AEAD
	ciphertext, nonce, tag, err := s.cryptoService.Encrypt(ctx, plaintext, payload.KID)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt payload: %w", err)
	}

	// Encode as base64url: <ciphertext>.<nonce>.<tag>
	token := fmt.Sprintf("%s.%s.%s",
		base64.URLEncoding.EncodeToString(ciphertext),
		base64.URLEncoding.EncodeToString(nonce),
		base64.URLEncoding.EncodeToString(tag),
	)

	// Remove padding
	token = strings.ReplaceAll(token, "=", "")

	return token, nil
}

// Validate decrypts and validates an opaque token
func (s *opaqueTokenServiceImpl) Validate(ctx context.Context, token string) (*OpaqueTokenPayload, error) {
	// Parse token format: <ciphertext>.<nonce>.<tag>
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	// Decode base64url (add padding if needed)
	ciphertext, err := base64.URLEncoding.DecodeString(addPadding(parts[0]))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid ciphertext encoding", ErrInvalidToken)
	}

	nonce, err := base64.URLEncoding.DecodeString(addPadding(parts[1]))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid nonce encoding", ErrInvalidToken)
	}

	tag, err := base64.URLEncoding.DecodeString(addPadding(parts[2]))
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tag encoding", ErrInvalidToken)
	}

	// We need to extract KID from the token somehow
	// For simplicity, we'll try all keys (in production, KID could be prepended)
	// Try current key first
	currentKID := s.cryptoService.GetCurrentKeyID(ctx)
	plaintext, err := s.cryptoService.Decrypt(ctx, ciphertext, nonce, tag, currentKID)
	if err != nil {
		// Token might have been encrypted with old key
		// In production, store KID in token or try multiple keys
		return nil, fmt.Errorf("failed to decrypt token: %w", err)
	}

	// Unmarshal payload
	var payload OpaqueTokenPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("%w: invalid payload", ErrInvalidToken)
	}

	// Validate expiry
	if payload.IsExpired() {
		return nil, ErrTokenExpired
	}

	// Validate audience
	if payload.Aud != s.cfg.ProxyURL {
		return nil, ErrInvalidAudience
	}

	// Decrypt access token if present
	if payload.AccessToken != "" {
		decryptedAccessToken, err := s.decryptToken(ctx, payload.AccessToken, payload.KID)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt access token: %w", err)
		}
		payload.AccessToken = decryptedAccessToken
	}

	// Decrypt refresh token if present
	if payload.RefreshToken != "" {
		decryptedRefreshToken, err := s.decryptToken(ctx, payload.RefreshToken, payload.KID)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt refresh token: %w", err)
		}
		payload.RefreshToken = decryptedRefreshToken
	}

	return &payload, nil
}

// encryptToken encrypts a single token (access or refresh token)
func (s *opaqueTokenServiceImpl) encryptToken(ctx context.Context, token string, kid string) (string, error) {
	plaintext := []byte(token)

	// Encrypt using AEAD
	ciphertext, nonce, tag, err := s.cryptoService.Encrypt(ctx, plaintext, kid)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt: %w", err)
	}

	// Encode as base64url: <ciphertext>.<nonce>.<tag>
	encrypted := fmt.Sprintf("%s.%s.%s",
		base64.URLEncoding.EncodeToString(ciphertext),
		base64.URLEncoding.EncodeToString(nonce),
		base64.URLEncoding.EncodeToString(tag),
	)

	// Remove padding
	encrypted = strings.ReplaceAll(encrypted, "=", "")
	return encrypted, nil
}

// decryptToken decrypts a single token (access or refresh token)
func (s *opaqueTokenServiceImpl) decryptToken(ctx context.Context, encryptedToken string, kid string) (string, error) {
	// Parse token format: <ciphertext>.<nonce>.<tag>
	parts := strings.Split(encryptedToken, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("invalid encrypted token format")
	}

	// Decode base64url (add padding if needed)
	ciphertext, err := base64.URLEncoding.DecodeString(addPadding(parts[0]))
	if err != nil {
		return "", fmt.Errorf("invalid ciphertext encoding: %w", err)
	}

	nonce, err := base64.URLEncoding.DecodeString(addPadding(parts[1]))
	if err != nil {
		return "", fmt.Errorf("invalid nonce encoding: %w", err)
	}

	tag, err := base64.URLEncoding.DecodeString(addPadding(parts[2]))
	if err != nil {
		return "", fmt.Errorf("invalid tag encoding: %w", err)
	}

	// Decrypt using AEAD
	plaintext, err := s.cryptoService.Decrypt(ctx, ciphertext, nonce, tag, kid)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt: %w", err)
	}

	return string(plaintext), nil
}

// addPadding adds base64 padding if needed
func addPadding(s string) string {
	switch len(s) % 4 {
	case 2:
		return s + "=="
	case 3:
		return s + "="
	default:
		return s
	}
}
