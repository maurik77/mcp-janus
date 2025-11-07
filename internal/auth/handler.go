// internal/auth/handler.go
package auth

import (
	"encoding/json"
	"mcpproxy/internal/config"
	"net/http"
	"time"
)

type PKCECode struct {
	CodeVerifier string `json:"v"`
	ClientID     string `json:"c"`
	Resource     string `json:"r"`
	State        string `json:"s"`
	ExpiresAt    int64  `json:"exp"`
}

// /register → client_id stateless
func RegisterHandler(w http.ResponseWriter, r *http.Request, cfg *config.Config, key [32]byte) {
	var req struct {
		RedirectURI string `json:"redirect_uri"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	payload := struct {
		RedirectURI string `json:"r"`
		IssuedAt    int64  `json:"iat"`
	}{req.RedirectURI, time.Now().Unix()}
	data, _ := json.Marshal(payload)
	clientID, _ := Encrypt(data, key)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"client_id": "cli_" + clientID,
	})
}
