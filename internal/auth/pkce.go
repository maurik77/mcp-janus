package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

func GeneratePKCE() (verifier, challenge string) {
	b := make([]byte, 64)
	rand.Read(b)
	verifier = base64.URLEncoding.EncodeToString(b)[:86]
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.URLEncoding.EncodeToString(h[:])
	return
}
