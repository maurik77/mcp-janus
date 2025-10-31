package proxy
package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mcpproxy/internal/config"
	"mcpproxy/internal/crypto"
	"mcpproxy/internal/mcp"
	"mcpproxy/internal/oauth"
	"mcpproxy/internal/tokens"
	pkghttp "mcpproxy/pkg/http"
)

func main() {
	// Load configuration
	cfg, err := config.LoadFromEnv()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	// Setup structured logging
	logLevel := slog.LevelInfo
	switch cfg.LogLevel {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	}

	var handler slog.Handler
	if cfg.LogFormat == "json" {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	} else {
		handler = slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: logLevel})
	}
	logger := slog.New(handler)
	slog.SetDefault(logger)

	slog.Info("starting MCP proxy server",
		"version", "1.0.0",
		"proxy_url", cfg.ProxyURL,
		"upstream_mcp_url", cfg.UpstreamMCPURL,
	)

	// Initialize crypto service
	cryptoService, err := crypto.NewAESGCMService(cfg)
	if err != nil {
		slog.Error("failed to initialize crypto service", "error", err)
		os.Exit(1)
	}

	// Initialize token store
	tokenStore, err := tokens.NewMemoryStore(cfg)
	if err != nil {
		slog.Error("failed to initialize token store", "error", err)
		os.Exit(1)
	}

	// Initialize opaque token service
	opaqueTokenService := tokens.NewOpaqueTokenService(cryptoService, cfg)

	// Initialize OAuth provider
	oauthProvider := oauth.NewProvider(cfg)

	// Initialize MCP client
	mcpClient := mcp.NewClient(cfg)

	// Create HTTP server with handlers
	server := pkghttp.NewServer(cfg, pkghttp.ServerDependencies{
		CryptoService:      cryptoService,
		TokenStore:         tokenStore,
		OpaqueTokenService: opaqueTokenService,
		OAuthProvider:      oauthProvider,
		MCPClient:          mcpClient,
	})

	// Setup HTTP server
	httpServer := &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      server.Handler(),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		var err error
		if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
			slog.Info("starting HTTPS server", "addr", cfg.ListenAddr)
			err = httpServer.ListenAndServeTLS(cfg.TLSCertFile, cfg.TLSKeyFile)
		} else {
			slog.Warn("starting HTTP server (TLS not configured)", "addr", cfg.ListenAddr)
			err = httpServer.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
			os.Exit(1)
		}
	}()

	slog.Info("server started successfully")

	// Wait for interrupt signal for graceful shutdown
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down server...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		slog.Error("server forced to shutdown", "error", err)
		os.Exit(1)
	}

	slog.Info("server exited gracefully")
}
