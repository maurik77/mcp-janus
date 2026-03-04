package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterWithKeycloakDCR(t *testing.T) {
	req := &RegisterRequest{
		ClientName:              "Test MCP Client",
		RedirectURIs:            []string{"http://localhost:3000/callback"},
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
	}

	t.Run("success with 201", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, http.MethodPost, r.Method)
			assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
			assert.Equal(t, "Bearer test-initial-token", r.Header.Get("Authorization"))

			var body RegisterRequest
			require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
			assert.Equal(t, req.ClientName, body.ClientName)

			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(keycloakDCRResponse{
				ClientID:     "kc-new-client-id",
				ClientSecret: "kc-new-client-secret",
				RedirectURIs: req.RedirectURIs,
			})
		}))
		defer srv.Close()

		resp, err := registerWithKeycloakDCR(srv.URL, "test-initial-token", req)
		require.NoError(t, err)
		assert.Equal(t, "kc-new-client-id", resp.ClientID)
		assert.Equal(t, "kc-new-client-secret", resp.ClientSecret)
		assert.Equal(t, req.RedirectURIs, resp.RedirectURIs)
	})

	t.Run("success with 200", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			json.NewEncoder(w).Encode(keycloakDCRResponse{
				ClientID:     "kc-client-200",
				ClientSecret: "kc-secret-200",
			})
		}))
		defer srv.Close()

		resp, err := registerWithKeycloakDCR(srv.URL, "", req)
		require.NoError(t, err)
		assert.Equal(t, "kc-client-200", resp.ClientID)
	})

	t.Run("no initial token omits Authorization header", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Empty(t, r.Header.Get("Authorization"))
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(keycloakDCRResponse{
				ClientID:     "no-auth-client",
				ClientSecret: "no-auth-secret",
			})
		}))
		defer srv.Close()

		_, err := registerWithKeycloakDCR(srv.URL, "", req)
		require.NoError(t, err)
	})

	t.Run("server returns 401", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		_, err := registerWithKeycloakDCR(srv.URL, "bad-token", req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "401")
	})

	t.Run("server returns 400", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusBadRequest)
		}))
		defer srv.Close()

		_, err := registerWithKeycloakDCR(srv.URL, "", req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "400")
	})

	t.Run("invalid response JSON", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte("not-json{{{"))
		}))
		defer srv.Close()

		_, err := registerWithKeycloakDCR(srv.URL, "", req)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "decode")
	})

	t.Run("invalid endpoint URL", func(t *testing.T) {
		_, err := registerWithKeycloakDCR("http://127.0.0.1:0/register", "", req)
		assert.Error(t, err)
	})
}
