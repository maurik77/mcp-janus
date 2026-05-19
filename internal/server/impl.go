package server

import (
	"context"
	"encoding/json"
	"fmt"
	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

type proxy struct {
	cfg          config.Config
	metadata     metadata.Service
	auth         auth.Service
	encryption   utility.Encryption
	tracer       trace.Tracer
	targetURL    *url.URL
	reverseProxy *httputil.ReverseProxy
}

type key int

const (
	keyRealToken key = iota
)

// NewProxy constructs the reverse proxy that decrypts opaque bearer tokens,
// validates the IdP JWT inside them, maps claims to upstream request headers,
// and forwards the authenticated request to the configured upstream MCP server.
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

	rp := &httputil.ReverseProxy{}
	rp.Rewrite = func(pr *httputil.ProxyRequest) {
		pr.SetURL(targetURL)
		if realToken, ok := pr.In.Context().Value(keyRealToken).(string); ok {
			pr.Out.Header.Set("Authorization", "Bearer "+realToken)
		}
		utility.LogHttpRequest(pr.Out)
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		resp.Header.Del("Server")
		utility.LogHttpResponse(resp)
		span := trace.SpanFromContext(resp.Request.Context())
		span.SetAttributes(attribute.Int("http.status_code", resp.StatusCode))
		if resp.StatusCode >= 400 {
			span.SetStatus(codes.Error, "Upstream returned error")
		} else {
			span.SetStatus(codes.Ok, "Request proxied successfully")
		}
		return nil
	}

	utility.Logger.Info().
		Str("upstream_url", targetURL.String()).
		Str("upstream_name", cfg.Upstream.Name).
		Msg("Proxy initialized")

	return &proxy{
		cfg:          cfg,
		metadata:     metadata,
		auth:         auth,
		encryption:   encryption,
		tracer:       otel.Tracer("mcp-proxy.server"),
		targetURL:    targetURL,
		reverseProxy: rp,
	}, nil
}

// AuthMiddleware returns an http.Handler middleware that decrypts the opaque
// bearer token, validates the IdP JWT (or self-issued token) contained within,
// injects mapped claims as request headers, and calls the next handler.
// Requests with a missing or invalid token receive 401 Unauthorized.
func (p *proxy) AuthMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx, span := p.tracer.Start(r.Context(), "proxy.AuthMiddleware")
			defer span.End()

			token, ok := extractBearerToken(r)
			if !ok {
				utility.Logger.Warn().Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: missing or invalid bearer token")
				span.SetStatus(codes.Error, "Missing or invalid bearer token")
				w.Header().Set("WWW-Authenticate", p.metadata.WWWAuthenticateHeader())
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("Token extracted")

			data, err := p.encryption.Decrypt(token)
			if err != nil {
				utility.Logger.Warn().Err(err).Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: token decryption failed")
				span.RecordError(err)
				span.SetStatus(codes.Error, "Token decryption failed")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("Token decrypted")

			// Detect self-issued token by discriminator field "t":"si"
			var si auth.SelfIssuedTokenData
			if jsonErr := json.Unmarshal(data, &si); jsonErr == nil && si.Type == "si" {
				if time.Now().Unix() > si.ExpiresAt {
					utility.Logger.Warn().Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: self-issued token expired")
					span.SetStatus(codes.Error, "Self-issued token expired")
					http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
					return
				}
				for header, value := range si.Claims {
					r.Header.Set(header, value)
				}
				for header, value := range p.cfg.IDP.FixedHeaders {
					r.Header.Set(header, value)
				}
				ctx = context.WithValue(ctx, keyRealToken, token)
				span.AddEvent("Self-issued token validated")
				span.SetStatus(codes.Ok, "Authentication successful")
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}

			jwtToken, err := p.auth.ValidateJWT(ctx, string(data))
			if err != nil || !jwtToken.Valid {
				utility.Logger.Warn().Err(err).Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: JWT validation failed")
				if err != nil {
					span.RecordError(err)
				}
				span.SetStatus(codes.Error, "JWT validation failed")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			span.AddEvent("JWT validated")

			claims, ok := jwtToken.Claims.(jwt.MapClaims)
			if !ok {
				utility.Logger.Warn().Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: failed to parse JWT claims")
				span.SetStatus(codes.Error, "Failed to parse claims")
				http.Error(w, `{"error":"invalid_token"}`, http.StatusUnauthorized)
				return
			}

			if sub, ok := claims["sub"].(string); ok {
				span.SetAttributes(attribute.String("user.id", sub))
				utility.Logger.Info().Str("sub", sub).Str("remote_addr", r.RemoteAddr).Msg("AuthMiddleware: authentication successful")
			}

			ctx = context.WithValue(ctx, keyRealToken, token)

			for source, dest := range p.cfg.IDP.ClaimsMapping {
				if value, exists := claims[source]; exists {
					if strValue, ok := value.(string); ok {
						r.Header.Set(dest, strValue)
					}
				}
			}

			for header, value := range p.cfg.IDP.FixedHeaders {
				r.Header.Set(header, value)
			}

			span.SetStatus(codes.Ok, "Authentication successful")
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ProxyHandler attaches tracing attributes and delegates to the reverse proxy.
func (p *proxy) ProxyHandler(w http.ResponseWriter, r *http.Request) {
	_, span := p.tracer.Start(r.Context(), "proxy.ProxyHandler")
	defer span.End()

	span.SetAttributes(
		attribute.String("http.method", r.Method),
		attribute.String("http.path", r.URL.Path),
		attribute.String("upstream.name", p.cfg.Upstream.Name),
		attribute.String("upstream.target_url", p.targetURL.String()),
	)
	span.AddEvent("Forwarding request to upstream")
	utility.Logger.Info().
		Str("method", r.Method).
		Str("path", r.URL.Path).
		Str("upstream", p.cfg.Upstream.Name).
		Str("target_url", p.targetURL.String()).
		Msg("ProxyHandler: forwarding request to upstream")

	p.reverseProxy.ServeHTTP(w, r)
}

func extractBearerToken(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	if auth == "" || !strings.HasPrefix(auth, "Bearer ") {
		return "", false
	}
	return strings.TrimPrefix(auth, "Bearer "), true
}
