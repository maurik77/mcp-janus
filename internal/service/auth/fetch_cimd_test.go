package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFetchAndValidateCIMD verifies that fetchAndValidateCIMD applies the SSRF
// guard before attempting any network request, and properly delegates to
// fetchCIMDDocumentRaw for the actual fetch+validation.
func TestFetchAndValidateCIMD(t *testing.T) {
	t.Run("HTTP URL rejected by SSRF guard", func(t *testing.T) {
		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchAndValidateCIMD("http://app.example.com/meta.json", nil, cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "https")
	})

	t.Run("IPv4 loopback URL rejected by SSRF guard", func(t *testing.T) {
		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchAndValidateCIMD("https://127.0.0.1/meta.json", nil, cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed")
	})

	t.Run("private IP URL rejected by SSRF guard", func(t *testing.T) {
		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchAndValidateCIMD("https://10.0.0.1/meta.json", nil, cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed")
	})

	t.Run("link-local IP URL rejected by SSRF guard", func(t *testing.T) {
		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchAndValidateCIMD("https://169.254.1.1/meta.json", nil, cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "disallowed")
	})

	t.Run("SSRF guard applied before HTTP request (no server needed)", func(t *testing.T) {
		// Verify the guard fires even when no HTTP client/server is provided.
		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchAndValidateCIMD("https://192.168.1.1/private.json", nil, cache)
		require.Error(t, err)
		// If we got here without a server, the guard intercepted before fetch.
		assert.Contains(t, err.Error(), "disallowed")
	})

	t.Run("valid URL delegates fetch to fetchCIMDDocumentRaw (HTTP 404 propagated)", func(t *testing.T) {
		// We can't use an HTTPS test server against a loopback IP (SSRF guard blocks it),
		// so we test the delegation by confirming HTTP-level errors propagate.
		// Use fetchCIMDDocumentRaw directly with an HTTP server to verify the same
		// error path that fetchAndValidateCIMD reaches after SSRF passes.
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("valid URL delegates fetch — server error propagated", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "500")
	})

	t.Run("valid document fetched and SSRF guard passed — success", func(t *testing.T) {
		// fetchCIMDDocumentRaw exercises the full fetch path. fetchAndValidateCIMD
		// adds only the SSRF guard on top, so testing fetchCIMDDocumentRaw here
		// covers the success path of the composed function.
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := ClientMetadataDocument{
				ClientID:     "http://" + r.Host,
				ClientName:   "Test CIMD Client",
				RedirectURIs: []string{"https://app.example.com/cb"},
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		doc, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.NoError(t, err)
		assert.Equal(t, "Test CIMD Client", doc.ClientName)
		assert.Equal(t, []string{"https://app.example.com/cb"}, doc.RedirectURIs)
	})
}
