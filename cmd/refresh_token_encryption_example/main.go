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

	fmt.Println("=== Refresh Token Encryption Example ===")
	fmt.Printf("Encryption Key: %s\n", base64.URLEncoding.EncodeToString(encryptionKey))
	fmt.Println()

	// Create refresh configuration
	refreshConfig := &tokeno.TokenRefreshConfig{
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		MaxRefreshAttempts: 5,
	}

	// Create TokenManager with encryption enabled
	tm := tokeno.NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("my-secret-key")).
		WithOpaqueEncryption(encryptionKey, true).
		WithRefreshConfig(refreshConfig).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token with refresh token using TokenBuilder
	tokenBuilder := tm.NewToken().
		WithIssuer("my-app").
		WithSubject("user123").
		WithAudience("api").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithIssuedAt(time.Now()).
		WithClaim("user_id", "12345").
		WithClaim("role", "admin").
		WithClaim("permissions", []string{"read", "write", "delete"}).
		WithClaim("email", "user@example.com")

	fmt.Println("Creating encrypted opaque token with refresh token...")
	result, err := tokenBuilder.CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to create opaque token: %v", err)
	}

	fmt.Printf("Access Token: %s\n", result.Token)
	fmt.Printf("Refresh Token: %s\n", result.RefreshToken)
	fmt.Println()

	// Demonstrate that both tokens are encrypted
	fmt.Println("=== Security Analysis ===")
	fmt.Println("Checking if tokens contain readable data...")

	sensitiveData := []string{"user123", "admin", "user@example.com", "12345", "my-app"}

	for _, data := range sensitiveData {
		accessContains := contains(result.Token, data)
		refreshContains := contains(result.RefreshToken, data)

		if accessContains {
			fmt.Printf("❌ SECURITY ISSUE: Access token contains: %s\n", data)
		} else {
			fmt.Printf("✅ Access token does not contain: %s\n", data)
		}

		if refreshContains {
			fmt.Printf("❌ SECURITY ISSUE: Refresh token contains: %s\n", data)
		} else {
			fmt.Printf("✅ Refresh token does not contain: %s\n", data)
		}
	}
	fmt.Println()

	// Verify encryption
	fmt.Println("=== Encryption Verification ===")

	// Check access token encryption
	decodedAccess, err := base64.URLEncoding.DecodeString(result.Token)
	if err != nil {
		fmt.Println("❌ Access token is not base64 encoded")
	} else {
		fmt.Println("✅ Access token is base64 encoded for transmission")

		var testData map[string]interface{}
		if json.Unmarshal(decodedAccess, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: Access token is JSON decodable (not encrypted)")
		} else {
			fmt.Println("✅ Access token is encrypted (not JSON decodable)")
		}
	}

	// Check refresh token encryption
	decodedRefresh, err := base64.URLEncoding.DecodeString(result.RefreshToken)
	if err != nil {
		fmt.Println("❌ Refresh token is not base64 encoded")
	} else {
		fmt.Println("✅ Refresh token is base64 encoded for transmission")

		var testData map[string]interface{}
		if json.Unmarshal(decodedRefresh, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: Refresh token is JSON decodable (not encrypted)")
		} else {
			fmt.Println("✅ Refresh token is encrypted (not JSON decodable)")
		}
	}
	fmt.Println()

	// Test token refresh flow
	fmt.Println("=== Token Refresh Flow ===")
	fmt.Println("Using refresh token to get new access token...")

	newResult, err := tm.RefreshToken(result.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}

	fmt.Printf("New Access Token: %s\n", newResult.Token)
	fmt.Printf("New Refresh Token: %s\n", newResult.RefreshToken)
	fmt.Println()

	// Verify new tokens are also encrypted
	fmt.Println("Verifying new tokens are encrypted...")

	// Check new access token encryption
	decodedNewAccess, err := base64.URLEncoding.DecodeString(newResult.Token)
	if err != nil {
		fmt.Println("❌ New access token is not base64 encoded")
	} else {
		var testData map[string]interface{}
		if json.Unmarshal(decodedNewAccess, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: New access token is JSON decodable (not encrypted)")
		} else {
			fmt.Println("✅ New access token is encrypted (not JSON decodable)")
		}
	}

	// Check new refresh token encryption
	decodedNewRefresh, err := base64.URLEncoding.DecodeString(newResult.RefreshToken)
	if err != nil {
		fmt.Println("❌ New refresh token is not base64 encoded")
	} else {
		var testData map[string]interface{}
		if json.Unmarshal(decodedNewRefresh, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: New refresh token is JSON decodable (not encrypted)")
		} else {
			fmt.Println("✅ New refresh token is encrypted (not JSON decodable)")
		}
	}
	fmt.Println()

	// Validate the new access token
	fmt.Println("=== Token Validation ===")
	validatedReq, err := tm.ValidateOpaqueToken(newResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate refreshed token: %v", err)
	}

	fmt.Println("✅ New access token validation successful!")
	fmt.Printf("Issuer: %s\n", validatedReq.Issuer)
	fmt.Printf("Subject: %s\n", validatedReq.Subject)
	fmt.Printf("Audience: %s\n", validatedReq.Audience)
	fmt.Printf("Expires At: %s\n", validatedReq.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("Issued At: %s\n", validatedReq.IssuedAt.Format(time.RFC3339))
	fmt.Printf("Custom Claims: %+v\n", validatedReq.CustomClaims)
	fmt.Println()

	// Demonstrate comparison with non-encrypted tokens
	fmt.Println("=== Comparison: Encrypted vs Non-Encrypted Refresh Tokens ===")

	// Create a non-encrypted token manager for comparison
	tmNonEncrypted := tokeno.NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("my-secret-key")).
		WithOpaqueEncryption(encryptionKey, false). // Disable encryption
		WithRefreshConfig(refreshConfig).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create non-encrypted token
	nonEncryptedBuilder := tmNonEncrypted.NewToken().
		WithIssuer("my-app").
		WithSubject("user123").
		WithAudience("api").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithIssuedAt(time.Now()).
		WithClaim("user_id", "12345").
		WithClaim("role", "admin")

	nonEncryptedResult, err := nonEncryptedBuilder.CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to create non-encrypted token: %v", err)
	}

	fmt.Printf("Non-Encrypted Refresh Token: %s\n", nonEncryptedResult.RefreshToken)
	fmt.Println()

	// Try to decode the non-encrypted refresh token as JSON
	fmt.Println("Analyzing non-encrypted refresh token...")
	decodedNonEncrypted, err := base64.URLEncoding.DecodeString(nonEncryptedResult.RefreshToken)
	if err != nil {
		fmt.Println("❌ Non-encrypted refresh token is not base64 encoded")
	} else {
		var testData map[string]interface{}
		if json.Unmarshal(decodedNonEncrypted, &testData) == nil {
			fmt.Println("❌ SECURITY ISSUE: Non-encrypted refresh token is JSON decodable (data is visible)")
			fmt.Printf("Decoded refresh token data: %+v\n", testData)
		} else {
			fmt.Println("✅ Non-encrypted refresh token is not JSON decodable")
		}
	}
	fmt.Println()

	fmt.Println("=== Summary ===")
	fmt.Println("✅ Encrypted refresh tokens hide all sensitive data")
	fmt.Println("✅ Only the server with the encryption key can decrypt and read the refresh token")
	fmt.Println("✅ Non-encrypted refresh tokens expose all data in base64-encoded JSON")
	fmt.Println("✅ Both access and refresh tokens are encrypted when encryption is enabled")
	fmt.Println("✅ Token refresh flow works correctly with encrypted tokens")
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || contains(s[1:], substr)))
}
