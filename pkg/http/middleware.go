package http

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// middlewareLogging logs all requests
func (s *Server) middlewareLogging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Generate request ID
		requestID := generateRequestID()

		// Add request ID to context (simplified - would use context.Context in production)
		w.Header().Set("X-Request-ID", requestID)

		// Log request (no sensitive data)
		slog.Info("request started",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)

		// Create response wrapper to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		// Log response
		duration := time.Since(start)
		slog.Info("request completed",
			"request_id", requestID,
			"method", r.Method,
			"path", r.URL.Path,
			"status", rw.statusCode,
			"duration_ms", duration.Milliseconds(),
		)
	})
}

// middlewareHTTPSEnforcement redirects HTTP to HTTPS (except localhost)
func (s *Server) middlewareHTTPSEnforcement(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip enforcement for localhost/127.0.0.1
		if s.isLocalhost(r) {
			next.ServeHTTP(w, r)
			return
		}

		// Skip if TLS is not configured (development mode)
		if s.cfg.TLSCertFile == "" || s.cfg.TLSKeyFile == "" {
			next.ServeHTTP(w, r)
			return
		}

		// Redirect HTTP to HTTPS
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			httpsURL := "https://" + r.Host + r.RequestURI
			http.Redirect(w, r, httpsURL, http.StatusMovedPermanently)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// isLocalhost checks if request is from localhost
func (s *Server) isLocalhost(r *http.Request) bool {
	host := r.Host
	return strings.HasPrefix(host, "localhost") ||
		strings.HasPrefix(host, "127.0.0.1") ||
		strings.HasPrefix(host, "[::1]")
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// generateRequestID generates a random request ID
func generateRequestID() string {
	b := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "unknown"
	}
	return base64.URLEncoding.EncodeToString(b)[:22]
}

// extractBearerToken extracts the token from Authorization header
func extractBearerToken(authHeader string) string {
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}
	return parts[1]
}

// writeJSON writes a JSON response
func writeJSON(w http.ResponseWriter, v interface{}) error {
	w.Header().Set("Content-Type", "application/json")
	return json.NewEncoder(w).Encode(v)
}

// readBody reads the request body
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	defer r.Body.Close()
	return io.ReadAll(r.Body)
}
