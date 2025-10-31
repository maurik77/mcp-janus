package mcp
package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"mcpproxy/internal/config"
)

var (
	// ErrForwardFailed indicates request forwarding failed
	ErrForwardFailed = errors.New("failed to forward request")
	// ErrUpstreamError indicates upstream server error
	ErrUpstreamError = errors.New("upstream server error")
)

// MCPClient forwards validated requests to upstream MCP server
type MCPClient interface {
	// Forward proxies an MCP request to the upstream server
	Forward(ctx context.Context, req *ProxyRequest) (*ProxyResponse, error)

	// DiscoverServer performs RFC 9728 discovery
	DiscoverServer(ctx context.Context, serverURL string) (*ProtectedResourceMetadata, error)
}

// ProxyRequest represents a validated request to be forwarded
type ProxyRequest struct {
	Method        string
	Path          string
	Headers       http.Header
	Body          []byte
	UpstreamToken string // Token for upstream server
	UpstreamURL   string // Target MCP server URL
}

// ProxyResponse from upstream server
type ProxyResponse struct {
	StatusCode int
	Headers    http.Header
	Body       []byte
}

// ProtectedResourceMetadata from RFC 9728
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceDocumentation  string   `json:"resource_documentation,omitempty"`
}

// mcpClientImpl implements MCPClient
type mcpClientImpl struct {
	cfg        *config.Config
	httpClient *http.Client
}

// NewClient creates a new MCP client
func NewClient(cfg *config.Config) MCPClient {
	return &mcpClientImpl{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 60 * time.Second,
		},
	}
}

// Forward proxies an MCP request to the upstream server
func (c *mcpClientImpl) Forward(ctx context.Context, req *ProxyRequest) (*ProxyResponse, error) {
	// Construct upstream URL
	upstreamURL := req.UpstreamURL + req.Path

	// Create HTTP request
	var bodyReader io.Reader
	if len(req.Body) > 0 {
		bodyReader = bytes.NewReader(req.Body)
	}

	httpReq, err := http.NewRequestWithContext(ctx, req.Method, upstreamURL, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create upstream request: %w", err)
	}

	// Copy headers (except Authorization)
	for key, values := range req.Headers {
		if key == "Authorization" {
			continue // We'll set our own
		}
		for _, value := range values {
			httpReq.Header.Add(key, value)
		}
	}

	// Set Authorization header with upstream token
	if req.UpstreamToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+req.UpstreamToken)
	}

	// Execute request
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrForwardFailed, err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read upstream response: %w", err)
	}

	return &ProxyResponse{
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Body:       body,
	}, nil
}

// DiscoverServer performs RFC 9728 discovery
func (c *mcpClientImpl) DiscoverServer(ctx context.Context, serverURL string) (*ProtectedResourceMetadata, error) {
	discoveryURL := serverURL + "/.well-known/oauth-protected-resource"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery failed with status %d", resp.StatusCode)
	}

	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to decode metadata: %w", err)
	}

	return &metadata, nil
}
