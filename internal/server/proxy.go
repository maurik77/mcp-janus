// internal/server/proxy.go
package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"mcpproxy/internal/auth"
	"mcpproxy/internal/config"
)

// extractBearerToken extracts token from Authorization header
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(auth, "Bearer "), true
}

// AuthMiddleware validates opaque_token and injects real token + upstream
func AuthMiddleware(cfg *config.Config, key [32]byte) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := extractBearerToken(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", WWWAuthenticateHeader(cfg.Proxy.BaseURL))
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// Decrypt opaque token
			data, err := auth.Decrypt(token, key)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			var t auth.OpaqueToken
			if err := json.Unmarshal(data, &t); err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// Validate expiration
			if time.Now().Unix() > t.ExpiresAt {
				http.Error(w, `{"error":"expired_token"}`, http.StatusUnauthorized)
				return
			}

			// Find upstream by resource
			var upstream *config.Upstream
			for _, u := range cfg.Upstreams {
				if u.Resource == t.Resource {
					upstream = &u
					break
				}
			}
			if upstream == nil {
				http.Error(w, `{"error":"invalid_resource"}`, http.StatusForbidden)
				return
			}

			// Inject into context
			ctx := context.WithValue(r.Context(), "real_token", t.AccessToken)
			ctx = context.WithValue(ctx, "upstream", *upstream)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ProxyHandler forwards request to correct upstream
func ProxyHandler(w http.ResponseWriter, r *http.Request) {
	upstream := r.Context().Value("upstream").(config.Upstream)
	realToken := r.Context().Value("real_token").(string)

	// Build target URL
	targetURL, _ := url.Parse(upstream.BaseURL)
	targetURL.Path = upstream.PathPrefix + r.URL.Path

	// Create reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(targetURL)

	// Modify request
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = targetURL.Host
		req.Header.Set("Authorization", "Bearer "+realToken)
		// Copy all headers except Host
		for k, v := range r.Header {
			if k != "Host" {
				req.Header[k] = v
			}
		}
	}

	// Modify response (optional)
	proxy.ModifyResponse = func(resp *http.Response) error {
		// Remove security headers from upstream if needed
		resp.Header.Del("Server")
		return nil
	}

	proxy.ServeHTTP(w, r)
}
