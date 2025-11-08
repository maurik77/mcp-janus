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
	"mcpproxy/internal/infrastructure/wire"
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

	r, err := wire.NewGinEngine(cfg, authService, metadataService, encryption)
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
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
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
