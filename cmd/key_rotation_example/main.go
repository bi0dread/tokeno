package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno Key Rotation Example ===\n")

	// Create a temporary directory for key storage
	tempDir, err := os.MkdirTemp("", "tokeno_keys")
	if err != nil {
		log.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fmt.Printf("Using key directory: %s\n\n", tempDir)

	// Configure key rotation
	keyConfig := tokeno.KeyRotationConfig{
		KeyDirectory:     tempDir,
		RotationInterval: 2 * time.Second, // Rotate every 2 seconds for demo
		KeyLifetime:      5 * time.Second, // Keys live for 5 seconds
		CleanupInterval:  1 * time.Second, // Cleanup every 1 second
		MaxKeyVersions:   3,               // Keep max 3 key versions
	}

	// Create KeyManager
	km, err := tokeno.NewKeyManager(keyConfig)
	if err != nil {
		log.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	fmt.Println("1. Initial Key Generation:")
	fmt.Println("==========================")

	// Generate initial HMAC key
	hmacKey, err := km.GenerateNewKey(tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to generate HMAC key: %v", err)
	}

	fmt.Printf("Generated HMAC Key: %s\n", hmacKey.ID)
	fmt.Printf("Method: %s\n", hmacKey.Method)
	fmt.Printf("Created: %s\n", hmacKey.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Expires: %s\n", hmacKey.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Is Active: %t\n", hmacKey.IsActive)
	fmt.Printf("Token Count: %d\n\n", hmacKey.TokenCount)

	// Generate initial RSA key
	rsaKey, err := km.GenerateNewKey(tokeno.SigningMethodRS256)
	if err != nil {
		log.Fatalf("Failed to generate RSA key: %v", err)
	}

	fmt.Printf("Generated RSA Key: %s\n", rsaKey.ID)
	fmt.Printf("Method: %s\n", rsaKey.Method)
	fmt.Printf("Created: %s\n", rsaKey.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Expires: %s\n", rsaKey.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Is Active: %t\n", rsaKey.IsActive)
	fmt.Printf("Token Count: %d\n\n", rsaKey.TokenCount)

	fmt.Println("2. Key Persistence Test:")
	fmt.Println("=======================")

	// Simulate some token usage
	fmt.Println("Simulating token usage...")
	for i := 0; i < 5; i++ {
		if err := km.IncrementTokenCount(rsaKey.ID); err != nil {
			log.Printf("Failed to increment token count: %v", err)
		}
	}

	// Get updated key info
	updatedRSAKey, err := km.GetKeyByID(rsaKey.ID)
	if err != nil {
		log.Fatalf("Failed to get updated RSA key: %v", err)
	}

	fmt.Printf("RSA Key Token Count: %d\n", updatedRSAKey.TokenCount)

	// List all key versions
	versions := km.GetKeyVersions()
	fmt.Printf("Total key versions: %d\n", len(versions))
	for _, version := range versions {
		fmt.Printf("  - %s (%s) - Active: %t, Tokens: %d\n",
			version.ID, version.Method, version.IsActive, version.TokenCount)
	}
	fmt.Println()

	fmt.Println("3. Key Rotation Demo:")
	fmt.Println("====================")

	// Demonstrate key rotation
	for i := 0; i < 3; i++ {
		fmt.Printf("Rotation %d:\n", i+1)

		// Rotate to new HMAC key
		newHMACKey, err := km.RotateKey(tokeno.SigningMethodHS256)
		if err != nil {
			log.Printf("Failed to rotate HMAC key: %v", err)
			continue
		}

		fmt.Printf("  New HMAC Key: %s\n", newHMACKey.ID)
		fmt.Printf("  Created: %s\n", newHMACKey.CreatedAt.Format(time.RFC3339))
		fmt.Printf("  Is Active: %t\n", newHMACKey.IsActive)

		// Get current active key
		currentKey, err := km.GetCurrentKey()
		if err != nil {
			log.Printf("Failed to get current key: %v", err)
		} else {
			fmt.Printf("  Current Active Key: %s\n", currentKey.ID)
		}

		// List all versions
		versions := km.GetKeyVersions()
		fmt.Printf("  Total versions: %d\n", len(versions))

		time.Sleep(1 * time.Second)
		fmt.Println()
	}

	fmt.Println("4. Key Cleanup Demo:")
	fmt.Println("===================")

	// Wait for some keys to expire
	fmt.Println("Waiting for keys to expire...")
	time.Sleep(6 * time.Second)

	// Note: Cleanup happens automatically in background
	// km.cleanupExpiredKeys() // This is a private method

	// List remaining versions
	versions = km.GetKeyVersions()
	fmt.Printf("Remaining key versions after cleanup: %d\n", len(versions))
	for _, version := range versions {
		fmt.Printf("  - %s (%s) - Active: %t, Tokens: %d, Expires: %s\n",
			version.ID, version.Method, version.IsActive, version.TokenCount,
			version.ExpiresAt.Format(time.RFC3339))
	}
	fmt.Println()

	fmt.Println("5. File System Check:")
	fmt.Println("====================")

	// List files in key directory
	files, err := filepath.Glob(filepath.Join(tempDir, "*.json"))
	if err != nil {
		log.Printf("Failed to list key files: %v", err)
	} else {
		fmt.Printf("Key files on disk: %d\n", len(files))
		for _, file := range files {
			fmt.Printf("  - %s\n", filepath.Base(file))
		}
	}
	fmt.Println()

	fmt.Println("6. Token Creation with Key Rotation:")
	fmt.Println("====================================")

	// Create a TokenManager that uses the KeyManager
	tmConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey:      []byte("fallback-secret"),
		OpaqueSecretKey:   []byte("fallback-opaque-secret"),
		DefaultExpiration: 1 * time.Hour,
	}

	tm := tokeno.NewTokenManager(tmConfig)

	// Create some tokens using the current key
	tokenReq := tokeno.TokenRequest{
		Issuer:    "key-rotation-service",
		Subject:   "user123",
		Audience:  "api-clients",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
		},
	}

	// Create JWT token
	jwtResult, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		log.Printf("Failed to create JWT token: %v", err)
	} else {
		fmt.Printf("Created JWT token: %s...\n", jwtResult.Token[:50])
		fmt.Printf("Token type: %s\n", jwtResult.Type)
		fmt.Printf("Expires at: %s\n", jwtResult.ExpiresAt.Format(time.RFC3339))
	}

	// Create opaque token
	opaqueResult, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		log.Printf("Failed to create opaque token: %v", err)
	} else {
		fmt.Printf("Created opaque token: %s...\n", opaqueResult.Token[:50])
		fmt.Printf("Token type: %s\n", opaqueResult.Type)
		fmt.Printf("Expires at: %s\n", opaqueResult.ExpiresAt.Format(time.RFC3339))
	}

	fmt.Println("\n=== Key Rotation Example Complete ===")
}
