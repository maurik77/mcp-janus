// cmd/proxy/main.go
package main

import (
	"context"
	"fmt"
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
		fmt.Print("Failed to load config")
		os.Exit(1)
	}

	utility.ConfigureLogging(cfg.Proxy.LogLevel, cfg.Proxy.LogFormat)

	// Initialize OpenTelemetry
	ctx := context.Background()

	telem, shutdownTelemetry, err := telemetry.Initialize(ctx, cfg.Telemetry)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize telemetry")
	}
	defer shutdownTelemetry()

	// Initialize metrics
	metrics, err := telemetry.InitializeMetrics(telem.Meter)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize metrics")
	}

	encryption, err := utility.NewEncryption(cfg)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize encryption")
	}

	authService, err := auth.New(*cfg, encryption)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize auth handler")
	}

	metadataService, err := metadata.New(*cfg)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize metadata handler")
	}

	proxy, err := server.NewProxy(*cfg, metadataService, authService, encryption)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize proxy")
	}

	r, err := wire.NewGinEngine(cfg, authService, metadataService, proxy, encryption, metrics)
	if err != nil {
		utility.Logger.Fatal().Err(err).Msg("Failed to initialize Gin engine")
	}

	srv := &http.Server{
		Addr:    cfg.Proxy.ListenAddr,
		Handler: r,
	}

	go func() {
		utility.Logger.Info().Str("addr", cfg.Proxy.ListenAddr).Msg("MCP Proxy Server starting")
		utility.Logger.Info().Str("base_url", cfg.Proxy.BaseURL).Msg("Base URL")

		var err error

		if cfg.Proxy.TLS {
			err = srv.ListenAndServeTLS(cfg.Proxy.TLSCertFile, cfg.Proxy.TLSKeyFile)
		} else {
			err = srv.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			utility.Logger.Fatal().Err(err).Msg("Server failed")
		}
	}()

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	utility.Logger.Info().Msg("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		utility.Logger.Fatal().Err(err).Msg("Server forced to shutdown")
	}
	utility.Logger.Info().Msg("Server stopped.")
}
