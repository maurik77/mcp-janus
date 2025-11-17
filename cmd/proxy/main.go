// cmd/proxy/main.go
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mcpproxy/internal/infrastructure/config"
	"mcpproxy/internal/infrastructure/telemetry"
	"mcpproxy/internal/infrastructure/wire"
	"mcpproxy/internal/server"
	"mcpproxy/internal/service/auth"
	"mcpproxy/internal/service/metadata"
	"mcpproxy/internal/utility"
)

func main() {
	var err error
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize OpenTelemetry
	ctx := context.Background()
	telemetryConfig := telemetry.Config{
		ServiceName:    cfg.Telemetry.ServiceName,
		ServiceVersion: cfg.Telemetry.ServiceVersion,
		OTLPEndpoint:   cfg.Telemetry.OTLPEndpoint,
		Enabled:        cfg.Telemetry.Enabled,
	}

	if telemetryConfig.ServiceName == "" {
		telemetryConfig.ServiceName = "mcp-proxy"
	}
	if telemetryConfig.ServiceVersion == "" {
		telemetryConfig.ServiceVersion = "1.0.0"
	}
	if telemetryConfig.OTLPEndpoint == "" {
		telemetryConfig.OTLPEndpoint = "localhost:4318"
	}

	telem, err := telemetry.Initialize(ctx, telemetryConfig)
	if err != nil {
		log.Fatalf("Failed to initialize telemetry: %v", err)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := telem.Shutdown(shutdownCtx); err != nil {
			log.Printf("Error shutting down telemetry: %v", err)
		}
	}()

	// Initialize metrics
	metrics, err := telemetry.InitializeMetrics(telem.Meter)
	if err != nil {
		log.Fatalf("Failed to initialize metrics: %v", err)
	}

	encryption, err := utility.NewEncryption(cfg)
	if err != nil {
		log.Fatalf("Failed to initialize encryption: %v", err)
	}

	authService, err := auth.New(*cfg, encryption)
	if err != nil {
		log.Fatalf("Failed to initialize auth handler: %v", err)
	}

	metadataService, err := metadata.New(*cfg)
	if err != nil {
		log.Fatalf("Failed to initialize metadata handler: %v", err)
	}

	proxy, err := server.NewProxy(*cfg, metadataService, authService, encryption)
	if err != nil {
		log.Fatalf("Failed to initialize proxy: %v", err)
	}

	r, err := wire.NewGinEngine(cfg, authService, metadataService, proxy, encryption, metrics)
	if err != nil {
		log.Fatalf("Failed to initialize Gin engine: %v", err)
	}

	srv := &http.Server{
		Addr:    cfg.Proxy.ListenAddr,
		Handler: r,
	}

	go func() {
		log.Printf("MCP Proxy Server starting on %s", cfg.Proxy.ListenAddr)
		log.Printf("Base URL: %s", cfg.Proxy.BaseURL)

		var err error

		if cfg.Proxy.TLS {
			err = srv.ListenAndServeTLS(cfg.Proxy.TLSCertFile, cfg.Proxy.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}
	log.Println("Server stopped.")
}
