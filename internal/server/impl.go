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
}

type key int

const (
	keyRealToken key = iota
	keyUpstream
)

func NewProxy(cfg config.Config,
	metadata metadata.Service,
	auth auth.Service,
	encryption utility.Encryption) (Proxy, error) {
	return &proxy{
		cfg:        cfg,
		metadata:   metadata,
		auth:       auth,
		encryption: encryption,
		tracer:     otel.Tracer("mcp-proxy.server"),
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

			jwtToken, err := p.auth.ValidateJWT(string(data))
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
				panic("cannot parse claims")
			}

			// Add subject to span attributes
			if sub, ok := claims["sub"].(string); ok {
				span.SetAttributes(attribute.String("user.id", sub))
			}

			ctx = context.WithValue(ctx, keyRealToken, token)

			for source, dest := range p.cfg.IDP.ClaimsMapping {
				if value, exists := claims[source]; exists {
					r.Header.Add(dest, value.(string))
				}
			}

			ctx = context.WithValue(ctx, keyUpstream, p.cfg.Upstream)
			span.SetStatus(codes.Ok, "Authentication successful")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ProxyHandler forwards request to correct upstream
func (p *proxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	ctx, span := p.tracer.Start(r.Context(), "proxy.ProxyHandler")
	defer span.End()

	upstream := r.Context().Value("upstream").(config.Upstream)
	realToken := r.Context().Value("real_token").(string)

	span.SetAttributes(
		attribute.String("http.method", r.Method),
		attribute.String("http.path", r.URL.Path),
		attribute.String("upstream.name", upstream.Name),
		attribute.String("upstream.base_url", upstream.BaseURL),
	)

	// Build target URL
	targetURL, _ := url.Parse(upstream.BaseURL)
	targetURL.Path = upstream.PathPrefix + r.URL.Path

	span.SetAttributes(attribute.String("upstream.target_url", targetURL.String()))
	span.AddEvent("Forwarding request to upstream")

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
		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		if resp.StatusCode >= 400 {
			span.SetStatus(codes.Error, "Upstream returned error")
		} else {
			span.SetStatus(codes.Ok, "Request proxied successfully")
		}
		return nil
	}

	// Suppress unused variable warning
	_ = ctx

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
