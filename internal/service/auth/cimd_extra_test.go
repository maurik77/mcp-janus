package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TestForbiddenAuthMethods ---

func TestForbiddenAuthMethods(t *testing.T) {
	tests := []struct {
		name    string
		method  string
		wantErr bool
	}{
		{"none allowed", "none", false},
		{"private_key_jwt allowed", "private_key_jwt", false},
		{"empty allowed", "", false},
		{"client_secret_basic rejected", "client_secret_basic", true},
		{"client_secret_post rejected", "client_secret_post", true},
		{"client_secret_jwt rejected", "client_secret_jwt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				doc := ClientMetadataDocument{
					ClientID:                "http://" + r.Host,
					ClientName:              "Test",
					RedirectURIs:            []string{"http://localhost/cb"},
					TokenEndpointAuthMethod: tt.method,
				}
				_ = json.NewEncoder(w).Encode(doc)
			}))
			defer ts.Close()

			cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
			_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), "forbidden")
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// --- TestClientSecretInDocumentRejected ---

func TestClientSecretInDocumentRejected(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Manually craft JSON with client_secret (the struct field would be omitempty but we test the validation)
		_, _ = w.Write([]byte(`{
			"client_id":"http://` + r.Host + `",
			"client_name":"Bad Client",
			"redirect_uris":["http://localhost/cb"],
			"client_secret":"should-not-be-here"
		}`))
	}))
	defer ts.Close()

	cache := &cimdCache{entries: make(map[string]cimdCacheEntry)}
	_, err := fetchCIMDDocumentRaw(ts.URL, ts.Client(), cache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_secret")
}

// --- TestRedirectURIMatchesRegistered ---

func TestRedirectURIMatchesRegistered(t *testing.T) {
	registered := []string{
		"http://localhost/callback",
		"http://127.0.0.1/callback",
		"https://app.example.com/cb",
	}

	tests := []struct {
		name            string
		requested       string
		portInsensitive bool
		wantMatch       bool
	}{
		// Exact matches always work
		{"exact match localhost", "http://localhost/callback", false, true},
		{"exact match 127.0.0.1", "http://127.0.0.1/callback", false, true},
		{"exact match HTTPS", "https://app.example.com/cb", false, true},
		// No match
		{"different path", "http://localhost/other", false, false},
		{"different scheme", "https://localhost/callback", false, false},
		// Port-insensitive off — port differences are rejected
		{"with port, insensitive off", "http://localhost:3118/callback", false, false},
		// Port-insensitive on — localhost port difference accepted
		{"with port, insensitive on", "http://localhost:3118/callback", true, true},
		{"127.0.0.1 with port, insensitive on", "http://127.0.0.1:3118/callback", true, true},
		// Remote URIs always require exact match even with insensitive on
		{"remote with port insensitive on — rejected", "https://app.example.com:443/cb", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := redirectURIMatchesRegistered(tt.requested, registered, tt.portInsensitive)
			assert.Equal(t, tt.wantMatch, got)
		})
	}
}

// --- TestLocalhostPortInsensitiveMatch ---

func TestLocalhostPortInsensitiveMatch(t *testing.T) {
	tests := []struct {
		registered string
		requested  string
		want       bool
	}{
		{"http://localhost/callback", "http://localhost:3118/callback", true},
		{"http://localhost/callback", "http://localhost/callback", true},
		{"http://127.0.0.1/callback", "http://127.0.0.1:8080/callback", true},
		{"http://localhost/callback", "http://localhost:3118/other", false},  // different path
		{"http://localhost/callback", "https://localhost:3118/callback", false}, // different scheme
		{"https://app.example.com/cb", "https://app.example.com:443/cb", false}, // not localhost
	}

	for _, tt := range tests {
		t.Run(tt.registered+"→"+tt.requested, func(t *testing.T) {
			assert.Equal(t, tt.want, localhostPortInsensitiveMatch(tt.registered, tt.requested))
		})
	}
}
