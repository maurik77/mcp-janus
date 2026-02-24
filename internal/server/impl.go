package server

import (
	"context"
	"fmt"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type proxy struct {
	cfg        config.Config
	metadata   metadata.Service
	auth       auth.Service
	encryption utility.Encryption
	tracer     trace.Tracer
	targetURL  *url.URL
}

type key int

const (
	keyRealToken key = iota
)

func NewProxy(cfg config.Config,
	metadata metadata.Service,
	auth auth.Service,
	encryption utility.Encryption) (Proxy, error) {
	targetURL, err := url.Parse(cfg.Upstream.BaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream base_url %q: %w", cfg.Upstream.BaseURL, err)
	}
	if targetURL.Scheme == "" || targetURL.Host == "" {
		return nil, fmt.Errorf("upstream base_url %q must be an absolute URL with scheme and host", cfg.Upstream.BaseURL)
	}
	if cfg.Upstream.PathPrefix != "" {
		targetURL.Path = cfg.Upstream.PathPrefix
	}

	return &proxy{
		cfg:        cfg,
		metadata:   metadata,
		auth:       auth,
		encryption: encryption,
		tracer:     otel.Tracer("mcp-proxy.server"),
		targetURL:  targetURL,
	}, nil
}

// AuthMiddleware validates opaque_token and injects real token + upstream
func (p *proxy) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := p.tracer.Start(r.Context(), "proxy.AuthMiddleware")
			defer span.End()

			token, ok := extractBearerToken(r)
			if !ok {
				span.SetStatus(codes.Error, "Missing or invalid bearer token")
				w.Header().Set("WWW-Authenticate", p.metadata.WWWAuthenticateHeader())
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("Token extracted")

			// Decrypt opaque token
			data, err := p.encryption.Decrypt(token)
			if err != nil {
				span.RecordError(err)
				span.SetStatus(codes.Error, "Token decryption failed")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("Token decrypted")

			jwtToken, err := p.auth.ValidateJWT(ctx, string(data))
			if err != nil || !jwtToken.Valid {
				if err != nil {
					span.RecordError(err)
				}
				span.SetStatus(codes.Error, "JWT validation failed")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("JWT validated")

			// Extract claims
			claims, ok := jwtToken.Claims.(jwt.MapClaims)
			if !ok {
				span.SetStatus(codes.Error, "Failed to parse claims")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			// Add subject to span attributes
			if sub, ok := claims["sub"].(string); ok {
				span.SetAttributes(attribute.String("user.id", sub))
			}

			ctx = context.WithValue(ctx, keyRealToken, token)

			for source, dest := range p.cfg.IDP.ClaimsMapping {
				if value, exists := claims[source]; exists {
					if strValue, ok := value.(string); ok {
						r.Header.Add(dest, strValue)
					}
				}
			}

			span.SetStatus(codes.Ok, "Authentication successful")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ProxyHandler forwards request to correct upstream
func (p *proxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	_, span := p.tracer.Start(r.Context(), "proxy.ProxyHandler")
	defer span.End()

	realToken := r.Context().Value(keyRealToken).(string)

	span.SetAttributes(
		attribute.String("http.method", r.Method),
		attribute.String("http.path", r.URL.Path),
		attribute.String("upstream.name", p.cfg.Upstream.Name),
		attribute.String("upstream.target_url", p.targetURL.String()),
	)
	span.AddEvent("Forwarding request to upstream")

	reverseProxy := httputil.NewSingleHostReverseProxy(p.targetURL)

	originalDirector := reverseProxy.Director
	reverseProxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = p.targetURL.Host
		req.Header.Set("Authorization", "Bearer "+realToken)
		for k, v := range r.Header {
			if k != "Host" {
				req.Header[k] = v
			}
		}

		utility.LogHttpRequest(req)
	}

	reverseProxy.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Server")

		utility.LogHttpResponse(resp)

		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		if resp.StatusCode >= 400 {
			span.SetStatus(codes.Error, "Upstream returned error")
		} else {
			span.SetStatus(codes.Ok, "Request proxied successfully")
		}
		return nil
	}

	reverseProxy.ServeHTTP(w, r)
}

// extractBearerToken extracts token from Authorization header
func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(auth, "Bearer "), true
}
