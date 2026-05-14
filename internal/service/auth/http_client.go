package auth

import (
	"crypto/tls"
	"net/http"
)

func newHTTPClient(skipTLSVerify bool) *http.Client {
	if !skipTLSVerify {
		return http.DefaultClient
	}
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
	}
}
