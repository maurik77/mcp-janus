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
	ClientID                string   `json:"client_id"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
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
