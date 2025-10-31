package scripts
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
)

// KeyStoreData represents the structure of the key store file
type KeyStoreData struct {
	Keys       map[string]string `json:"keys"`
	CurrentKID string            `json:"current_kid"`
}

func main() {
	keyStorePathPtr := flag.String("path", "./keys.json", "Path to key store file")
	flag.Parse()

	keyStorePath := *keyStorePathPtr

	fmt.Println("MCP Proxy - Key Generation Utility")
	fmt.Println("===================================")
	fmt.Printf("Key store path: %s\n\n", keyStorePath)

	// Generate new key (256 bits for AES-256)
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Generate KID
	kidBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, kidBytes); err != nil {
		log.Fatalf("Failed to generate KID: %v", err)
	}
	kid := base64.URLEncoding.EncodeToString(kidBytes)
	kid = strings.TrimRight(kid, "=")

	fmt.Printf("Generated new key:\n")
	fmt.Printf("  KID: %s\n", kid)
	fmt.Printf("  Key: %s (hex)\n", fmt.Sprintf("%x", key))
	fmt.Println()

	// Load or create key store
	var data KeyStoreData
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		// Create new key store
		data = KeyStoreData{
			Keys: make(map[string]string),
		}
		fmt.Println("Creating new key store...")
	} else {
		// Load existing key store
		content, err := os.ReadFile(keyStorePath)
		if err != nil {
			log.Fatalf("Failed to read key store: %v", err)
		}

		if err := json.Unmarshal(content, &data); err != nil {
			log.Fatalf("Failed to parse key store: %v", err)
		}

		fmt.Printf("Loaded existing key store with %d key(s)\n", len(data.Keys))
	}

	// Add new key
	data.Keys[kid] = string(key)
	data.CurrentKID = kid

	// Save key store
	content, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal key store: %v", err)
	}

	if err := os.WriteFile(keyStorePath, content, 0600); err != nil {
		log.Fatalf("Failed to write key store: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ Key generated and saved successfully")
	fmt.Printf("✓ Current KID set to: %s\n", kid)
	fmt.Printf("✓ Total keys in store: %d\n", len(data.Keys))
	fmt.Println()
	fmt.Println("IMPORTANT: Keep this key store file secure!")
	fmt.Println("  - Set permissions to 600")
	fmt.Println("  - Never commit to version control")
	fmt.Println("  - Back up securely")
}
