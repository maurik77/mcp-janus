package auth

import (
	"encoding/json"
	"fmt"
	"mcpproxy/internal/utility"
	"net/url"
)

type RegisterRequest struct {
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type RegisterResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type AuthenticateRequest struct {
	ClientID            string `json:"client_id", form:"client_id"`
	State               string `json:"state", form:"state"`
	CodeChallenge       string `json:"code_challenge", form:"code_challenge"`
	RedirectURI         string `json:"redirect_uri", form:"redirect_uri"`
	CodeChallengeMethod string `json:"code_challenge_method", form:"code_challenge_method"`
}

type AuthorizationCodeData struct {
	State string `json:"state"`
	Code  string `json:"code"`
}

type AccessTokenRequest struct {
	Code         string `json:"code", form:"code"`
	RedirectURI  string `json:"redirect_uri", form:"redirect_uri"`
	ClientSecret string `json:"client_secret", form:"client_secret"`
	CodeVerifier string `json:"code_verifier", form:"code_verifier"`
	ClientID     string `json:"client_id", form:"client_id"`
}

type ClientIdData struct {
	RedirectURIs []string `json:"r"`
	Secret       string   `json:"s"`
}

func (c *ClientIdData) Encode(key [32]byte) (string, error) {
	dataJSON, err := json.Marshal(c)
	if err != nil {
		return "", err
	}
	encrypted, err := utility.Encrypt(dataJSON, key)
	if err != nil {
		return "", err
	}

	return encrypted, nil
}

func DecodeClientID(encrypted string, key [32]byte) (*ClientIdData, error) {
	data, err := utility.Decrypt(encrypted, key)
	if err != nil {
		return nil, err
	}
	var cid *ClientIdData
	if err := json.Unmarshal(data, cid); err != nil {
		return nil, err
	}

	return cid, nil
}

type StateData struct {
	OriginalState string `json:"s"`
	RedirectURI   string `json:"e"`
}

func (s *StateData) Encode() string {
	// concatenate OriginalState and RedirectURI with a separator | and url encode
	encoded := url.QueryEscape(s.OriginalState + "|" + s.RedirectURI)
	return encoded
}

func DecodeStateData(encoded string) (*StateData, error) {
	decoded, err := url.QueryUnescape(encoded)
	if err != nil {
		return nil, err
	}
	parts := make([]string, 2)
	splitIndex := -1
	for i, c := range decoded {
		if c == '|' {
			splitIndex = i
			break
		}
	}
	if splitIndex == -1 {
		return nil, fmt.Errorf("invalid state data")
	}
	parts[0] = decoded[:splitIndex]
	parts[1] = decoded[splitIndex+1:]

	return &StateData{
		OriginalState: parts[0],
		RedirectURI:   parts[1],
	}, nil
}
