package auth

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

type keycloakDCRResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret"`
	RegistrationAccessToken string   `json:"registration_access_token"`
	RedirectURIs            []string `json:"redirect_uris"`
}

// registerWithKeycloakDCR creates a new client in Keycloak via RFC 7591 DCR.
func registerWithKeycloakDCR(registrationEndpoint, initialToken string, req *RegisterRequest) (*keycloakDCRResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal DCR request: %w", err)
	}

	httpReq, err := http.NewRequest(http.MethodPost, registrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create DCR request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if initialToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+initialToken)
	}

	resp, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to register client with Keycloak: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Keycloak DCR failed with HTTP %d", resp.StatusCode)
	}

	var dcrResp keycloakDCRResponse
	if err := json.NewDecoder(resp.Body).Decode(&dcrResp); err != nil {
		return nil, fmt.Errorf("failed to decode Keycloak DCR response: %w", err)
	}

	return &dcrResp, nil
}
