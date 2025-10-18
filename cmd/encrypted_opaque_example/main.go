package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		log.Fatalf("Failed to generate encryption key: %v", err)
	}

	fmt.Println("=== Encrypted Opaque Token Example ===")
	fmt.Printf("Encryption Key: %s\n", base64.URLEncoding.EncodeToString(encryptionKey))
	fmt.Println()

	// Create TokenManager with encryption enabled
	tm := tokeno.NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("my-secret-key")).
		WithOpaqueEncryption(encryptionKey, true).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token request with sensitive data
	req := tokeno.TokenRequest{
		Issuer:    "my-app",
		Subject:   "user123",
		Audience:  "api",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"user_id":     "12345",
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
			"secret_key":  "super-secret-key-123",
			"email":       "user@example.com",
		},
	}

	fmt.Println("Creating encrypted opaque token...")
	fmt.Printf("Original claims: %+v\n", req.CustomClaims)
	fmt.Println()

	// Create opaque token
	result, err := tm.CreateOpaqueToken(req)
	if err != nil {
		log.Fatalf("Failed to create opaque token: %v", err)
	}

	fmt.Printf("Encrypted Token: %s\n", result.Token)
	fmt.Println()

	// Demonstrate that the token is encrypted (not readable)
	fmt.Println("=== Security Analysis ===")
	fmt.Println("Checking if token contains readable data...")

	tokenStr := result.Token
	sensitiveData := []string{"user123", "admin", "super-secret-key-123", "user@example.com", "12345"}

	for _, data := range sensitiveData {
		if contains(tokenStr, data) {
			fmt.Printf("❌ SECURITY ISSUE: Token contains readable data: %s\n", data)
		} else {
			fmt.Printf("✅ Token does not contain: %s\n", data)
		}
	}
	fmt.Println()

	// Try to decode as JSON (should fail for encrypted tokens)
	fmt.Println("Attempting to decode token as JSON...")
	decodedBytes, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		fmt.Println("❌ Token is not base64 encoded")
	} else {
		fmt.Println("✅ Token is base64 encoded for transmission")

		var testData map[string]interface{}
		if json.Unmarshal(decodedBytes, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: Token is JSON decodable (not encrypted)")
		} else {
			fmt.Println("✅ Token is encrypted (not JSON decodable)")
		}
	}
	fmt.Println()

	// Validate the token
	fmt.Println("=== Token Validation ===")
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		log.Fatalf("Failed to validate opaque token: %v", err)
	}

	fmt.Println("✅ Token validation successful!")
	fmt.Printf("Issuer: %s\n", validatedReq.Issuer)
	fmt.Printf("Subject: %s\n", validatedReq.Subject)
	fmt.Printf("Audience: %s\n", validatedReq.Audience)
	fmt.Printf("Expires At: %s\n", validatedReq.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Issued At: %s\n", validatedReq.IssuedAt.Format(time.RFC3339))
	fmt.Printf("Custom Claims: %+v\n", validatedReq.CustomClaims)
	fmt.Println()

	// Demonstrate with different encryption settings
	fmt.Println("=== Comparison: Encrypted vs Non-Encrypted ===")

	// Create a non-encrypted token for comparison
	tmNonEncrypted := tokeno.NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("my-secret-key")).
		WithOpaqueEncryption(encryptionKey, false). // Disable encryption
		WithDefaultExpiration(1 * time.Hour).
		Build()

	nonEncryptedResult, err := tmNonEncrypted.CreateOpaqueToken(req)
	if err != nil {
		log.Fatalf("Failed to create non-encrypted opaque token: %v", err)
	}

	fmt.Printf("Non-Encrypted Token: %s\n", nonEncryptedResult.Token)
	fmt.Println()

	// Try to decode the non-encrypted token as JSON
	fmt.Println("Analyzing non-encrypted token...")
	decodedBytes, err = base64.URLEncoding.DecodeString(nonEncryptedResult.Token)
	if err != nil {
		fmt.Println("❌ Non-encrypted token is not base64 encoded")
	} else {
		var testData map[string]interface{}
		if json.Unmarshal(decodedBytes, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: Non-encrypted token is JSON decodable (data is visible)")
			fmt.Printf("Decoded data: %+v\n", testData)
		} else {
			fmt.Println("✅ Non-encrypted token is not JSON decodable")
		}
	}
	fmt.Println()

	// Validate the non-encrypted token
	validatedNonEncryptedReq, err := tmNonEncrypted.ValidateOpaqueToken(nonEncryptedResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate non-encrypted opaque token: %v", err)
	}

	fmt.Println("✅ Non-encrypted token validation successful!")
	fmt.Printf("Custom Claims: %+v\n", validatedNonEncryptedReq.CustomClaims)
	fmt.Println()

	fmt.Println("=== Summary ===")
	fmt.Println("✅ Encrypted opaque tokens hide all sensitive data")
	fmt.Println("✅ Only the server with the encryption key can decrypt and read the token")
	fmt.Println("✅ Non-encrypted tokens expose all data in base64-encoded JSON")
	fmt.Println("✅ Both token types work correctly for authentication")
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || contains(s[1:], substr)))
}
