package server

import (
	"context"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type proxy struct {
	cfg        config.Config
	metadata   metadata.Service
	auth       auth.Service
	encryption utility.Encryption
}

func NewProxy(cfg config.Config,
	metadata metadata.Service,
	auth auth.Service,
	encryption utility.Encryption) (Proxy, error) {
	return &proxy{
		cfg:        cfg,
		metadata:   metadata,
		auth:       auth,
		encryption: encryption,
	}, nil
}

// AuthMiddleware validates opaque_token and injects real token + upstream
func (p *proxy) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, ok := extractBearerToken(r)
			if !ok {
				w.Header().Set("WWW-Authenticate", p.metadata.WWWAuthenticateHeader())
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// Decrypt opaque token
			data, err := p.encryption.Decrypt(token)
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// Unmarshal data into jwt.Token
			jwtToken, _, err := new(jwt.Parser).ParseUnverified(string(data), jwt.MapClaims{})
			if err != nil {
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// var t oauth2.Token
			// if err := json.Unmarshal(data, &t); err != nil {
			// 	http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
			// 	return
			// }

			// Validate expiration
			// if time.Now().Unix() > t.ExpiresIn {
			// 	http.Error(w, `{"error":"expired_token"}`, http.StatusUnauthorized)
			// 	return
			// }

			// Extract claims
			claims, ok := jwtToken.Claims.(jwt.MapClaims)
			if !ok {
				panic("cannot parse claims")
			}

			ctx := context.WithValue(r.Context(), "real_token", token)

			for source, dest := range p.cfg.IDP.ClaimsMapping {
				if value, exists := claims[source]; exists {
					r.Header.Add(dest, value.(string))
				}
			}

			ctx = context.WithValue(ctx, "upstream", p.cfg.Upstream)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ProxyHandler forwards request to correct upstream
func (p *proxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
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

// extractBearerToken extracts token from Authorization header
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(auth, "Bearer "), true
}
