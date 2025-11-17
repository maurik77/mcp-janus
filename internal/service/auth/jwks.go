package auth

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
)

type JWKS struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty       string `json:"kty"`
	Kid       string `json:"kid"`
	Use       string `json:"use"`
	N         string `json:"n"` // RSA modulus
	E         string `json:"e"` // RSA exponent
	Alg       string `json:"alg"`
	publicKey *rsa.PublicKey
}

func fetchJWKS(url string) (*JWKS, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log the error but don't override the main function error
			// In a real implementation, you might want to use structured logging here
			fmt.Printf("Error closing response body: %v\n", err)
		}
	}()

	var jwks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to decode JWKS: %w", err)
	}
	return &jwks, nil
}

// Convert a single JWK (RSA) into *rsa.PublicKey
func (j *JWK) RSAKey() (*rsa.PublicKey, error) {
	if j.publicKey != nil {
		return j.publicKey, nil
	}

	if j.Kty != "RSA" {
		return nil, fmt.Errorf("unsupported key type: %s", j.Kty)
	}

	nBytes, err := base64.RawURLEncoding.DecodeString(j.N)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 for modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(j.E)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 for exponent: %w", err)
	}

	// Convert exponent bytes to int
	var eInt int
	if len(eBytes) < 4 {
		eBytesPadded := make([]byte, 4-len(eBytes), 4)
		eBytes = append(eBytesPadded, eBytes...)
	}
	eInt = int(binary.BigEndian.Uint32(eBytes))

	j.publicKey = &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return j.publicKey, nil
}

func (jwks *JWKS) GetKeyByID(kid string) (*JWK, error) {
	for _, key := range jwks.Keys {
		if key.Kid == kid {
			return &key, nil
		}
	}
	return nil, fmt.Errorf("key not found")
}

func (jwks *JWKS) GetKeyByKID(kid string) *rsa.PublicKey {
	jwk, err := jwks.GetKeyByID(kid)
	if err != nil {
		return nil
	}
	publicKey, err := jwk.RSAKey()
	if err != nil {
		return nil
	}
	return publicKey
}
