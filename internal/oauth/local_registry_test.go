package oauth

import (
	"context"
	"strings"
	"testing"
)

func TestLocalClientRegistry_RegisterClient(t *testing.T) {
	registry := NewLocalClientRegistry()
	ctx := context.Background()

	req := &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test MCP Client",
		ClientURI:               "https://client.example.com",
	}

	resp, err := registry.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	// Verify response
	if resp.ClientID == "" {
		t.Error("Expected non-empty client_id")
	}

	if !strings.HasPrefix(resp.ClientID, "mcp-proxy-") {
		t.Errorf("Expected client_id to have 'mcp-proxy-' prefix, got %s", resp.ClientID)
	}

	if resp.ClientSecret == "" {
		t.Error("Expected non-empty client_secret for confidential client")
	}

	if resp.ClientIDIssuedAt == 0 {
		t.Error("Expected non-zero client_id_issued_at")
	}

	// Verify client can be retrieved
	client, err := registry.GetClient(ctx, resp.ClientID)
	if err != nil {
		t.Fatalf("GetClient failed: %v", err)
	}

	if client.ClientID != resp.ClientID {
		t.Errorf("Expected client_id %s, got %s", resp.ClientID, client.ClientID)
	}

	if client.ClientName != req.ClientName {
		t.Errorf("Expected client_name %s, got %s", req.ClientName, client.ClientName)
	}
}

func TestLocalClientRegistry_PublicClient(t *testing.T) {
	registry := NewLocalClientRegistry()
	ctx := context.Background()

	req := &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "none",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Public MCP Client",
	}

	resp, err := registry.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	if resp.ClientSecret != "" {
		t.Errorf("Expected empty client_secret for public client, got %s", resp.ClientSecret)
	}

	err = registry.ValidateClient(ctx, resp.ClientID, "")
	if err != nil {
		t.Errorf("ValidateClient for public client failed: %v", err)
	}
}

func TestLocalClientRegistry_ValidateClient(t *testing.T) {
	registry := NewLocalClientRegistry()
	ctx := context.Background()

	req := &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_post",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
	}

	resp, err := registry.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	err = registry.ValidateClient(ctx, resp.ClientID, resp.ClientSecret)
	if err != nil {
		t.Errorf("ValidateClient with correct credentials failed: %v", err)
	}

	err = registry.ValidateClient(ctx, resp.ClientID, "wrong-secret")
	if err == nil {
		t.Error("Expected error for invalid secret, got nil")
	}

	err = registry.ValidateClient(ctx, "non-existent-client", "secret")
	if err != ErrClientNotFound {
		t.Errorf("Expected ErrClientNotFound, got %v", err)
	}
}

func TestLocalClientRegistry_DeleteClient(t *testing.T) {
	registry := NewLocalClientRegistry()
	ctx := context.Background()

	req := &ClientRegistrationRequest{
		RedirectURIs:            []string{"https://client.example.com/callback"},
		TokenEndpointAuthMethod: "client_secret_basic",
		GrantTypes:              []string{"authorization_code"},
		ResponseTypes:           []string{"code"},
		ClientName:              "Test Client",
	}

	resp, err := registry.RegisterClient(ctx, req)
	if err != nil {
		t.Fatalf("RegisterClient failed: %v", err)
	}

	err = registry.DeleteClient(ctx, resp.ClientID)
	if err != nil {
		t.Errorf("DeleteClient failed: %v", err)
	}

	_, err = registry.GetClient(ctx, resp.ClientID)
	if err != ErrClientNotFound {
		t.Errorf("Expected ErrClientNotFound after deletion, got %v", err)
	}

	err = registry.DeleteClient(ctx, "non-existent-client")
	if err != ErrClientNotFound {
		t.Errorf("Expected ErrClientNotFound for non-existent client, got %v", err)
	}
}

func TestLocalClientRegistry_ValidationErrors(t *testing.T) {
	registry := NewLocalClientRegistry()
	ctx := context.Background()

	tests := []struct {
		name    string
		req     *ClientRegistrationRequest
		wantErr bool
	}{
		{
			name: "missing redirect_uris",
			req: &ClientRegistrationRequest{
				TokenEndpointAuthMethod: "client_secret_basic",
				GrantTypes:              []string{"authorization_code"},
			},
			wantErr: true,
		},
		{
			name: "empty redirect_uri",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{""},
				TokenEndpointAuthMethod: "client_secret_basic",
			},
			wantErr: true,
		},
		{
			name: "invalid auth method",
			req: &ClientRegistrationRequest{
				RedirectURIs:            []string{"https://example.com/callback"},
				TokenEndpointAuthMethod: "invalid_method",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := registry.RegisterClient(ctx, tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("RegisterClient() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
