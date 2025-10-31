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
	"time"
)

// KeyStoreData represents the structure of the key store file
type KeyStoreData struct {
	Keys       map[string]string `json:"keys"`
	CurrentKID string            `json:"current_kid"`
}

func main() {
	keyStorePathPtr := flag.String("path", "./keys.json", "Path to key store file")
	retainOldPtr := flag.Bool("retain", true, "Retain old keys for decryption")
	emergencyPtr := flag.Bool("emergency", false, "Emergency rotation (delete all old keys)")
	flag.Parse()

	keyStorePath := *keyStorePathPtr
	retainOld := *retainOldPtr
	emergency := *emergencyPtr

	fmt.Println("MCP Proxy - Key Rotation Utility")
	fmt.Println("=================================")
	fmt.Printf("Key store path: %s\n", keyStorePath)
	fmt.Printf("Retain old keys: %v\n", retainOld && !emergency)
	if emergency {
		fmt.Println("⚠️  EMERGENCY MODE: All old keys will be deleted!")
	}
	fmt.Println()

	// Load existing key store
	if _, err := os.Stat(keyStorePath); os.IsNotExist(err) {
		log.Fatalf("Key store not found: %s. Run gen-keys.go first.", keyStorePath)
	}

	content, err := os.ReadFile(keyStorePath)
	if err != nil {
		log.Fatalf("Failed to read key store: %v", err)
	}

	var data KeyStoreData
	if err := json.Unmarshal(content, &data); err != nil {
		log.Fatalf("Failed to parse key store: %v", err)
	}

	oldKID := data.CurrentKID
	oldKeyCount := len(data.Keys)

	fmt.Printf("Current KID: %s\n", oldKID)
	fmt.Printf("Current key count: %d\n", oldKeyCount)
	fmt.Println()

	// Generate new key
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		log.Fatalf("Failed to generate key: %v", err)
	}

	// Generate new KID
	kidBytes := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, kidBytes); err != nil {
		log.Fatalf("Failed to generate KID: %v", err)
	}
	newKID := base64.URLEncoding.EncodeToString(kidBytes)
	newKID = strings.TrimRight(newKID, "=")

	fmt.Printf("Generated new key:\n")
	fmt.Printf("  KID: %s\n", newKID)
	fmt.Println()

	// Handle emergency rotation
	if emergency {
		fmt.Println("⚠️  Deleting all old keys...")
		data.Keys = make(map[string]string)
	} else if !retainOld {
		// Delete old keys except current
		fmt.Printf("Deleting old keys (keeping current: %s)...\n", oldKID)
		newKeys := make(map[string]string)
		newKeys[oldKID] = data.Keys[oldKID]
		data.Keys = newKeys
	}

	// Add new key
	data.Keys[newKID] = string(key)
	data.CurrentKID = newKID

	// Create backup before saving
	backupPath := fmt.Sprintf("%s.backup.%d", keyStorePath, time.Now().Unix())
	if err := os.WriteFile(backupPath, content, 0600); err != nil {
		log.Printf("Warning: Failed to create backup: %v", err)
	} else {
		fmt.Printf("✓ Backup created: %s\n", backupPath)
	}

	// Save updated key store
	newContent, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		log.Fatalf("Failed to marshal key store: %v", err)
	}

	if err := os.WriteFile(keyStorePath, newContent, 0600); err != nil {
		log.Fatalf("Failed to write key store: %v", err)
	}

	fmt.Println()
	fmt.Println("✓ Key rotation completed successfully")
	fmt.Printf("✓ New KID: %s\n", newKID)
	fmt.Printf("✓ Old KID: %s\n", oldKID)
	fmt.Printf("✓ Total keys in store: %d\n", len(data.Keys))
	fmt.Println()

	if emergency {
		fmt.Println("⚠️  IMPORTANT: All old tokens are now INVALID!")
		fmt.Println("   Users must re-authenticate immediately.")
	} else if retainOld {
		fmt.Println("NOTE: Old tokens remain valid until expiry.")
		fmt.Println("      Old keys retained for decryption.")
	} else {
		fmt.Println("NOTE: Only current key retained.")
		fmt.Println("      Some old tokens may fail to validate.")
	}

	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Restart MCP proxy to load new key")
	fmt.Println("  2. Monitor logs for token validation failures")
	fmt.Println("  3. Consider cleaning up old keys after token TTL expires")
}
