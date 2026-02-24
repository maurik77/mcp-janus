package auth

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- TestFetchJWKS ---

func TestFetchJWKS(t *testing.T) {
	key := testRSAKey(t)

	t.Run("success", func(t *testing.T) {
		jwk := rsaPublicKeyToJWK(&key.PublicKey, "kid-1")
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(JWKS{Keys: []JWK{jwk}})
		}))
		defer ts.Close()

		jwks, err := fetchJWKS(ts.URL)
		require.NoError(t, err)
		require.Len(t, jwks.Keys, 1)
		assert.Equal(t, "kid-1", jwks.Keys[0].Kid)
		assert.Equal(t, "RSA", jwks.Keys[0].Kty)
		assert.Equal(t, "RS256", jwks.Keys[0].Alg)
	})

	t.Run("http error status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer ts.Close()

		_, err := fetchJWKS(ts.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 500")
	})

	t.Run("invalid json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte("not valid json{{{"))
		}))
		defer ts.Close()

		_, err := fetchJWKS(ts.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode JWKS")
	})

	t.Run("network error", func(t *testing.T) {
		_, err := fetchJWKS("http://127.0.0.1:1/nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch JWKS")
	})

	t.Run("multiple keys", func(t *testing.T) {
		key2 := testRSAKey(t)
		jwk1 := rsaPublicKeyToJWK(&key.PublicKey, "kid-1")
		jwk2 := rsaPublicKeyToJWK(&key2.PublicKey, "kid-2")
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(JWKS{Keys: []JWK{jwk1, jwk2}})
		}))
		defer ts.Close()

		jwks, err := fetchJWKS(ts.URL)
		require.NoError(t, err)
		assert.Len(t, jwks.Keys, 2)
		assert.Equal(t, "kid-1", jwks.Keys[0].Kid)
		assert.Equal(t, "kid-2", jwks.Keys[1].Kid)
	})
}

// --- TestFetchOpenIDConfiguration ---

func TestFetchOpenIDConfiguration(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(OpenIDConfiguration{
				Issuer:                "https://example.com",
				AuthorizationEndpoint: "https://example.com/authorize",
				TokenEndpoint:         "https://example.com/token",
				JWKSEndpoint:          "https://example.com/.well-known/jwks.json",
			})
		}))
		defer ts.Close()

		config, err := fetchOpenIDConfiguration(ts.URL)
		require.NoError(t, err)
		assert.Equal(t, "https://example.com", config.Issuer)
		assert.Equal(t, "https://example.com/authorize", config.AuthorizationEndpoint)
		assert.Equal(t, "https://example.com/token", config.TokenEndpoint)
		assert.Equal(t, "https://example.com/.well-known/jwks.json", config.JWKSEndpoint)
	})

	t.Run("http error status", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer ts.Close()

		_, err := fetchOpenIDConfiguration(ts.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "HTTP 404")
	})

	t.Run("invalid json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("{invalid"))
		}))
		defer ts.Close()

		_, err := fetchOpenIDConfiguration(ts.URL)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to decode OpenID configuration")
	})

	t.Run("network error", func(t *testing.T) {
		_, err := fetchOpenIDConfiguration("http://127.0.0.1:1/nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "failed to fetch OpenID configuration")
	})
}

// --- TestJWK_RSAKey ---

func TestJWK_RSAKey(t *testing.T) {
	t.Run("valid RSA key round-trip", func(t *testing.T) {
		origKey := testRSAKey(t)
		jwk := rsaPublicKeyToJWK(&origKey.PublicKey, "kid-1")

		pubKey, err := jwk.RSAKey()
		require.NoError(t, err)
		assert.Equal(t, 0, origKey.PublicKey.N.Cmp(pubKey.N), "modulus mismatch")
		assert.Equal(t, origKey.PublicKey.E, pubKey.E, "exponent mismatch")
	})

	t.Run("cached key on second call", func(t *testing.T) {
		origKey := testRSAKey(t)
		jwk := rsaPublicKeyToJWK(&origKey.PublicKey, "kid-1")

		key1, err := jwk.RSAKey()
		require.NoError(t, err)
		key2, err := jwk.RSAKey()
		require.NoError(t, err)

		// Same pointer = cached
		assert.Same(t, key1, key2)
	})

	t.Run("non-RSA key type", func(t *testing.T) {
		jwk := JWK{Kty: "EC", Kid: "kid-ec"}
		_, err := jwk.RSAKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported key type: EC")
	})

	t.Run("invalid N base64", func(t *testing.T) {
		jwk := JWK{Kty: "RSA", N: "!!!invalid!!!", E: "AQAB"}
		_, err := jwk.RSAKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64 for modulus")
	})

	t.Run("invalid E base64", func(t *testing.T) {
		origKey := testRSAKey(t)
		jwk := JWK{
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(origKey.PublicKey.N.Bytes()),
			E:   "!!!invalid!!!",
		}
		_, err := jwk.RSAKey()
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid base64 for exponent")
	})
}

// --- TestJWKS_GetKeyByID ---

func TestJWKS_GetKeyByID(t *testing.T) {
	key1 := testRSAKey(t)
	key2 := testRSAKey(t)

	jwks := &JWKS{
		Keys: []JWK{
			rsaPublicKeyToJWK(&key1.PublicKey, "kid-1"),
			rsaPublicKeyToJWK(&key2.PublicKey, "kid-2"),
		},
	}

	t.Run("key found", func(t *testing.T) {
		jwk, err := jwks.GetKeyByID("kid-1")
		require.NoError(t, err)
		assert.Equal(t, "kid-1", jwk.Kid)
		assert.Equal(t, "RSA", jwk.Kty)
	})

	t.Run("key found second entry", func(t *testing.T) {
		jwk, err := jwks.GetKeyByID("kid-2")
		require.NoError(t, err)
		assert.Equal(t, "kid-2", jwk.Kid)
	})

	t.Run("key not found", func(t *testing.T) {
		_, err := jwks.GetKeyByID("kid-nonexistent")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "key not found")
	})
}

// --- TestJWKS_GetKeyByKID ---

func TestJWKS_GetKeyByKID(t *testing.T) {
	key1 := testRSAKey(t)

	t.Run("returns RSA public key", func(t *testing.T) {
		jwks := &JWKS{
			Keys: []JWK{rsaPublicKeyToJWK(&key1.PublicKey, "kid-1")},
		}

		pubKey := jwks.GetKeyByKID("kid-1")
		require.NotNil(t, pubKey)
		assert.Equal(t, 0, key1.PublicKey.N.Cmp(pubKey.N))
		assert.Equal(t, key1.PublicKey.E, pubKey.E)
	})

	t.Run("returns nil for unknown kid", func(t *testing.T) {
		jwks := &JWKS{
			Keys: []JWK{rsaPublicKeyToJWK(&key1.PublicKey, "kid-1")},
		}

		pubKey := jwks.GetKeyByKID("kid-nonexistent")
		assert.Nil(t, pubKey)
	})

	t.Run("returns nil for non-RSA key", func(t *testing.T) {
		jwks := &JWKS{
			Keys: []JWK{{Kty: "EC", Kid: "kid-ec"}},
		}

		pubKey := jwks.GetKeyByKID("kid-ec")
		assert.Nil(t, pubKey)
	})

	t.Run("empty JWKS", func(t *testing.T) {
		jwks := &JWKS{Keys: []JWK{}}

		pubKey := jwks.GetKeyByKID("kid-1")
		assert.Nil(t, pubKey)
	})
}
