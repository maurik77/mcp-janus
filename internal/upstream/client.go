// internal/upstream/client.go
package upstream

import (
	"bytes"
	"io"
	"net/http"
	"time"
)

// Client is a reusable HTTP client for upstreams
var Client = &http.Client{
	Timeout: 30 * time.Second,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// Call makes a request to upstream with real token
func Call(upstreamURL, method, path, token string, body []byte) (*http.Response, error) {
	url := upstreamURL + path
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	if body != nil {
		req.Body = io.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}

	return Client.Do(req)
}

// HealthCheck pings upstream
func HealthCheck(baseURL string) bool {
	resp, err := http.Get(baseURL + "/health")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == 200
}
