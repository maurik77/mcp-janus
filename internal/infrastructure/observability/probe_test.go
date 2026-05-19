package observability

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr
}

func TestProbeServer_LiveEndpoint(t *testing.T) {
	addr := freeAddr(t)
	ps := NewProbeServer(addr)
	ps.Start()

	defer func() {
		_ = ps.Shutdown(context.Background())
	}()

	// Give the server a moment to bind
	assert.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/health/live")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond)
}

func TestProbeServer_ReadyEndpoint(t *testing.T) {
	addr := freeAddr(t)
	ps := NewProbeServer(addr)
	ps.Start()

	defer func() {
		_ = ps.Shutdown(context.Background())
	}()

	assert.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/health/ready")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond)
}

func TestProbeServer_Shutdown(t *testing.T) {
	addr := freeAddr(t)
	ps := NewProbeServer(addr)
	ps.Start()

	assert.Eventually(t, func() bool {
		resp, err := http.Get("http://" + addr + "/health/live")
		if err != nil {
			return false
		}
		_ = resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, 2*time.Second, 50*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := ps.Shutdown(ctx)
	assert.NoError(t, err)

	// After shutdown, the port must be released
	assert.Eventually(t, func() bool {
		_, err := http.Get("http://" + addr + "/health/live")
		return err != nil
	}, 2*time.Second, 50*time.Millisecond)
}
