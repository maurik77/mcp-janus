package server

import (
	"context"
	"io"
	"mcpproxy/internal/infrastructure/config"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProxyHandler_ForwardsRequestToUpstream(t *testing.T) {
	var capturedMethod, capturedPath string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedMethod = r.Method
		capturedPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"result":"ok"}`))
	}))
	defer upstream.Close()

	p, err := NewProxy(config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/resource", nil)
	rec := httptest.NewRecorder()
	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "GET", capturedMethod)
	assert.Equal(t, "/mcp/resource", capturedPath)
}

func TestProxyHandler_RewritesAuthorizationHeaderFromContext(t *testing.T) {
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, err := NewProxy(config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/", nil)
	req.Header.Set("Authorization", "Bearer opaque-token") // client-facing token
	ctx := context.WithValue(req.Context(), keyRealToken, "real-idp-jwt")
	rec := httptest.NewRecorder()

	p.ProxyHandler(rec, req.WithContext(ctx))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "Bearer real-idp-jwt", capturedAuth)
}

func TestProxyHandler_NoContextTokenKeepsOriginalHeader(t *testing.T) {
	var capturedAuth string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, err := NewProxy(config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/", nil)
	req.Header.Set("Authorization", "Bearer original-token")
	rec := httptest.NewRecorder()

	p.ProxyHandler(rec, req) // no keyRealToken in context

	assert.Equal(t, http.StatusOK, rec.Code)
	// Without keyRealToken in context, no overwrite happens — original header survives.
	assert.Equal(t, "Bearer original-token", capturedAuth)
}

func TestProxyHandler_PassesThroughUpstreamStatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"400 Bad Request", http.StatusBadRequest},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
			}))
			defer upstream.Close()

			p, err := NewProxy(config.Config{
				Upstream: config.Upstream{BaseURL: upstream.URL},
			}, nil, nil)
			require.NoError(t, err)

			req := httptest.NewRequest("GET", "/mcp/test", nil)
			rec := httptest.NewRecorder()
			p.ProxyHandler(rec, req)

			assert.Equal(t, tt.statusCode, rec.Code)
		})
	}
}

func TestProxyHandler_ForwardsPOSTBody(t *testing.T) {
	var capturedBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstream.Close()

	p, err := NewProxy(config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}, nil, nil)
	require.NoError(t, err)

	body := strings.NewReader(`{"jsonrpc":"2.0","method":"tools/list"}`)
	req := httptest.NewRequest("POST", "/mcp/", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusAccepted, rec.Code)
	assert.JSONEq(t, `{"jsonrpc":"2.0","method":"tools/list"}`, string(capturedBody))
}

func TestProxyHandler_ServerHeaderStripped(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "upstream-server/1.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	p, err := NewProxy(config.Config{
		Upstream: config.Upstream{BaseURL: upstream.URL},
	}, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/mcp/", nil)
	rec := httptest.NewRecorder()
	p.ProxyHandler(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Header().Get("Server"))
}
