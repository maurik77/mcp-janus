package auth

import (
	"encoding/json"
	"fmt"
	"mcpproxy/internal/utility"
)

type RegisterRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type RegisterResponse struct {
	// Server-generated fields (RFC 7591 §3.2.1)
	ClientID              string `json:"client_id"`
	ClientSecret          string `json:"client_secret,omitempty"`
	ClientIDIssuedAt      int64  `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`

	// Client metadata echo-back (MUST per RFC 7591 §3.2.1)
	ClientName              string   `json:"client_name,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
}

type AuthenticateRequest struct {
	ClientID            string `json:"client_id" form:"client_id"`
	State               string `json:"state" form:"state"`
	CodeChallenge       string `json:"code_challenge" form:"code_challenge"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri"`
	CodeChallengeMethod string `json:"code_challenge_method" form:"code_challenge_method"`
	Resource            string `json:"resource" form:"resource"`
}

type AuthorizationCodeData struct {
	State string `json:"state" form:"state"`
	Code  string `json:"code" form:"code"`
}

type AccessTokenRequest struct {
	Code                string `json:"code" form:"code"`
	RedirectURI         string `json:"redirect_uri" form:"redirect_uri"`
	ClientSecret        string `json:"client_secret" form:"client_secret"`
	CodeVerifier        string `json:"code_verifier" form:"code_verifier"`
	ClientID            string `json:"client_id" form:"client_id"`
	GrantTypes          string `json:"grant_type" form:"grant_type"`
	Resource            string `json:"resource" form:"resource"`
	ClientAssertionType string `json:"client_assertion_type" form:"client_assertion_type"`
	ClientAssertion     string `json:"client_assertion" form:"client_assertion"`
}

type RefreshTokenRequest struct {
	GrantType    string `json:"grant_type"    form:"grant_type"`
	RefreshToken string `json:"refresh_token" form:"refresh_token"`
	ClientID     string `json:"client_id"     form:"client_id"`
	ClientSecret string `json:"client_secret" form:"client_secret"`
}

type ClientIDData struct {
	RedirectURIs []string `json:"r"`
	Secret       string   `json:"s"`
}

func (c *ClientIDData) Encode(encryption utility.Encryption) (string, error) {
	dataJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encrypted, err := encryption.Encrypt(dataJSON)
	if err != nil {
		return "", err
	}

	return encrypted, nil
}

func DecodeClientID(encrypted string, encryption utility.Encryption) (*ClientIDData, error) {
	data, err := encryption.Decrypt(encrypted)
	if err != nil {
		return nil, err
	}
	var cid ClientIDData
	if err := json.Unmarshal(data, &cid); err != nil {
		return nil, err
	}

	return &cid, nil
}

type SelfIssuedTokenData struct {
	Type      string            `json:"t"`
	ExpiresAt int64             `json:"exp"`
	IssuedAt  int64             `json:"iat"`
	Claims    map[string]string `json:"cl"`
}

func (s *SelfIssuedTokenData) Encode(encryption utility.Encryption) (string, error) {
	data, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("failed to marshal self-issued token: %w", err)
	}
	encrypted, err := encryption.Encrypt(data)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt self-issued token: %w", err)
	}
	return encrypted, nil
}

func DecodeSelfIssuedToken(encrypted string, encryption utility.Encryption) (*SelfIssuedTokenData, error) {
	data, err := encryption.Decrypt(encrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt self-issued token: %w", err)
	}
	var si SelfIssuedTokenData
	if err := json.Unmarshal(data, &si); err != nil {
		return nil, fmt.Errorf("failed to unmarshal self-issued token: %w", err)
	}
	if si.Type != "si" {
		return nil, fmt.Errorf("not a self-issued token")
	}
	return &si, nil
}

type StateData struct {
	OriginalState string `json:"s"`
	RedirectURI   string `json:"r"`
	ClientID      string `json:"c"`
	Resource      string `json:"res,omitempty"`
}

func (s *StateData) Encode(encryption utility.Encryption) (string, error) {
	dataJSON, err := json.Marshal(s)
	if err != nil {
		return "", fmt.Errorf("failed to marshal state data: %w", err)
	}
	encrypted, err := encryption.Encrypt(dataJSON)
	if err != nil {
		return "", fmt.Errorf("failed to encrypt state data: %w", err)
	}
	return encrypted, nil
}

func DecodeStateData(encoded string, encryption utility.Encryption) (*StateData, error) {
	data, err := encryption.Decrypt(encoded)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt state data: %w", err)
	}
	var state StateData
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state data: %w", err)
	}
	return &state, nil
}
