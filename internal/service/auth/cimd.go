package auth

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const cimdCacheTTL = 5 * time.Minute

// ClientMetadataDocument is the OAuth Client ID Metadata Document
// (draft-ietf-oauth-client-id-metadata-document-00).
type ClientMetadataDocument struct {
	ClientID                    string   `json:"client_id"`
	ClientName                  string   `json:"client_name"`
	ClientURI                   string   `json:"client_uri,omitempty"`
	LogoURI                     string   `json:"logo_uri,omitempty"`
	RedirectURIs                []string `json:"redirect_uris"`
	GrantTypes                  []string `json:"grant_types,omitempty"`
	ResponseTypes               []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod     string   `json:"token_endpoint_auth_method,omitempty"`
	TokenEndpointAuthSigningAlg string   `json:"token_endpoint_auth_signing_alg,omitempty"`
	JwksURI                     string   `json:"jwks_uri,omitempty"`
	// ClientSecret must never be present in a valid CIMD document (spec §4).
	ClientSecret string `json:"client_secret,omitempty"`
}

// forbiddenAuthMethods lists token_endpoint_auth_method values that are symmetric
// (require a shared secret) and therefore prohibited in CIMD documents (spec §4).
var forbiddenAuthMethods = map[string]bool{
	"client_secret_basic": true,
	"client_secret_post":  true,
	"client_secret_jwt":   true,
}

type cimdCacheEntry struct {
	doc     *ClientMetadataDocument
	expires time.Time
}

type cimdCache struct {
	mu      sync.RWMutex
	entries map[string]cimdCacheEntry
}

func (c *cimdCache) get(rawURL string) (*ClientMetadataDocument, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	entry, ok := c.entries[rawURL]
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	return entry.doc, true
}

func (c *cimdCache) set(rawURL string, doc *ClientMetadataDocument) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[rawURL] = cimdCacheEntry{doc: doc, expires: time.Now().Add(cimdCacheTTL)}
}

// isURLClientID returns true when client_id is an HTTPS URL (CIMD flow).
func isURLClientID(s string) bool {
	return strings.HasPrefix(s, "https://")
}

// validateCIMDURL rejects non-HTTPS and private/loopback IP-literal URLs to prevent SSRF.
// Note: DNS rebinding protection requires a custom dialer and is out of scope here.
func validateCIMDURL(rawURL string) error {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid client_id URL: %w", err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("client_id URL must use https scheme, got %q", parsed.Scheme)
	}
	host := parsed.Hostname()
	if host == "" {
		return fmt.Errorf("client_id URL missing host")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
			return fmt.Errorf("client_id URL host is a disallowed IP address")
		}
	}
	return nil
}

// fetchCIMDDocumentRaw fetches and validates a CIMD document without applying SSRF checks.
// Callers are responsible for validating the URL first. Results are cached for cimdCacheTTL.
func fetchCIMDDocumentRaw(rawURL string, client *http.Client, cache *cimdCache) (*ClientMetadataDocument, error) {
	if doc, ok := cache.get(rawURL); ok {
		return doc, nil
	}

	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Get(rawURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("failed to fetch client metadata document: %w", err)
	}
	defer resp.Body.Close() //nolint:errcheck

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("client metadata document returned HTTP %d", resp.StatusCode)
	}

	var doc ClientMetadataDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode client metadata document: %w", err)
	}

	if doc.ClientID != rawURL {
		return nil, fmt.Errorf("client_id in document %q does not match URL", doc.ClientID)
	}
	if doc.ClientName == "" {
		return nil, fmt.Errorf("client metadata document missing required field: client_name")
	}
	if len(doc.RedirectURIs) == 0 {
		return nil, fmt.Errorf("client metadata document missing required field: redirect_uris")
	}
	if doc.ClientSecret != "" {
		return nil, fmt.Errorf("client metadata document must not contain client_secret")
	}
	if forbiddenAuthMethods[doc.TokenEndpointAuthMethod] {
		return nil, fmt.Errorf("client metadata document uses forbidden auth method: %q", doc.TokenEndpointAuthMethod)
	}

	cache.set(rawURL, &doc)
	return &doc, nil
}

// fetchAndValidateCIMD applies an SSRF guard then fetches and validates the document.
func fetchAndValidateCIMD(rawURL string, client *http.Client, cache *cimdCache) (*ClientMetadataDocument, error) {
	if err := validateCIMDURL(rawURL); err != nil {
		return nil, err
	}
	return fetchCIMDDocumentRaw(rawURL, client, cache)
}

// redirectURIMatchesRegistered checks whether the requested redirect URI matches
// one of the registered URIs in the document.  When portInsensitive is true,
// localhost / 127.0.0.1 URIs are compared ignoring the port component — this
// accommodates Claude Code's published CIMD document, which lists portless URIs
// (http://localhost/callback) while the actual callback server listens on a
// dynamically chosen port (e.g. http://localhost:3118/callback).
func redirectURIMatchesRegistered(requested string, registered []string, portInsensitive bool) bool {
	for _, r := range registered {
		if r == requested {
			return true
		}
		if portInsensitive && localhostPortInsensitiveMatch(r, requested) {
			return true
		}
	}
	return false
}

// localhostPortInsensitiveMatch returns true when both URIs share the same scheme,
// a localhost / 127.0.0.1 host, and the same path+query — ignoring port.
func localhostPortInsensitiveMatch(registered, requested string) bool {
	reg, err1 := url.Parse(registered)
	req, err2 := url.Parse(requested)
	if err1 != nil || err2 != nil {
		return false
	}
	if reg.Scheme != req.Scheme {
		return false
	}
	regHost := reg.Hostname()
	reqHost := req.Hostname()
	if !isLocalhost(regHost) || !isLocalhost(reqHost) {
		return false
	}
	return reg.Path == req.Path && reg.RawQuery == req.RawQuery
}

func isLocalhost(host string) bool {
	return host == "localhost" || host == "127.0.0.1"
}
