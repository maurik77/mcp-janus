package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TestValidateCIMDURL ---

func TestValidateCIMDURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		wantErr     bool
		errContains string
	}{
		{
			name: "valid https URL",
			url:  "https://app.example.com/oauth/metadata.json",
		},
		{
			name:        "http scheme rejected",
			url:         "http://app.example.com/metadata.json",
			wantErr:     true,
			errContains: "https",
		},
		{
			name:        "loopback IP rejected",
			url:         "https://127.0.0.1/metadata.json",
			wantErr:     true,
			errContains: "disallowed",
		},
		{
			name:        "private IP 10.x rejected",
			url:         "https://10.0.0.1/metadata.json",
			wantErr:     true,
			errContains: "disallowed",
		},
		{
			name:        "private IP 192.168.x rejected",
			url:         "https://192.168.1.1/metadata.json",
			wantErr:     true,
			errContains: "disallowed",
		},
		{
			name:        "link-local IP rejected",
			url:         "https://169.254.1.1/metadata.json",
			wantErr:     true,
			errContains: "disallowed",
		},
		{
			name:        "IPv6 loopback rejected",
			url:         "https://[::1]/metadata.json",
			wantErr:     true,
			errContains: "disallowed",
		},
		{
			name:        "missing host",
			url:         "https:///path",
			wantErr:     true,
			errContains: "missing host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCIMDURL(tt.url)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errContains != "" {
					assert.Contains(t, err.Error(), tt.errContains)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// --- TestFetchCIMDDocumentRaw ---

func cimdTestServer(t *testing.T, doc ClientMetadataDocument, statusCode int) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if statusCode != http.StatusOK {
			w.WriteHeader(statusCode)
			return
		}
		_ = json.NewEncoder(w).Encode(doc)
	}))
}

func TestFetchCIMDDocumentRaw(t *testing.T) {
	t.Run("valid document", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			path := r.URL.Path
			if path == "/" {
				path = ""
			}
			doc := ClientMetadataDocument{
				ClientID:     "http://" + r.Host + path,
				ClientName:   "Test Client",
				RedirectURIs: []string{"http://localhost:3000/callback"},
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		doc, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.NoError(t, err)
		assert.Equal(t, "Test Client", doc.ClientName)
		assert.Equal(t, []string{"http://localhost:3000/callback"}, doc.RedirectURIs)
	})

	t.Run("client_id mismatch", func(t *testing.T) {
		ts := cimdTestServer(t, ClientMetadataDocument{
			ClientID:     "https://different.example.com/meta.json",
			ClientName:   "Test Client",
			RedirectURIs: []string{"http://localhost/cb"},
		}, http.StatusOK)
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not match URL")
	})

	t.Run("missing client_name", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := ClientMetadataDocument{
				ClientID:     "http://" + r.Host,
				RedirectURIs: []string{"http://localhost/cb"},
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_name")
	})

	t.Run("missing redirect_uris", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			doc := ClientMetadataDocument{
				ClientID:   "http://" + r.Host,
				ClientName: "Test Client",
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "redirect_uris")
	})

	t.Run("non-200 response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "404")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("not json"))
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.Error(t, err)
	})

	t.Run("cache hit avoids second request", func(t *testing.T) {
		callCount := 0
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			doc := ClientMetadataDocument{
				ClientID:     "http://" + r.Host,
				ClientName:   "Test Client",
				RedirectURIs: []string{"http://localhost/cb"},
			}
			_ = json.NewEncoder(w).Encode(doc)
		}))
		defer ts.Close()

		cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
		_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.NoError(t, err)
		_, err = fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
		require.NoError(t, err)
		assert.Equal(t, 1, callCount, "second call should use cache")
	})
}
