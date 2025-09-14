package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno RefreshConfig Builder Example ===")
	fmt.Println("Using TokenManagerBuilder with WithRefreshConfig method")
	fmt.Println()

	// Create TokenManager using the builder pattern with refresh configuration
	tm := tokeno.NewTokenManagerBuilder().
		WithJWTSecret([]byte("your-jwt-secret-key")).
		WithJWTMethod(tokeno.SigningMethodHS256).
		WithDefaultExpiration(1 * time.Hour).
		WithRefreshConfig(&tokeno.TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,   // Refresh 30 minutes before expiry
			MaxRefreshAttempts: 5,                  // Allow 5 refresh attempts
			RefreshGracePeriod: 5 * time.Minute,    // 5 minute grace period
			RefreshTokenLength: 64,                 // 64 character refresh tokens
			RefreshTokenExpiry: 7 * 24 * time.Hour, // Refresh tokens valid for 7 days
		}).
		Build()

	// 1. Create JWT Token with Auto-Generated Refresh Token
	fmt.Println("1. Creating JWT Token with Auto-Generated Refresh Token:")
	fmt.Println("========================================================")

	jwtResult, err := tm.NewToken().
		WithIssuer("tokeno-service").
		WithSubject("user123").
		WithAudience("api-clients").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithClaim("role", "admin").
		WithClaim("permissions", []string{"read", "write", "delete"}).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create JWT token: %v", err)
	}

	fmt.Printf("✅ JWT Access Token: %s...\n", jwtResult.Token[:50])
	fmt.Printf("✅ JWT Refresh Token: %s...\n", jwtResult.RefreshToken[:50])
	fmt.Printf("✅ Access Token Expires At: %s\n", jwtResult.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Token Type: %s\n", jwtResult.Type)

	// 2. Demonstrate Refresh Token Usage
	fmt.Println("\n2. Using Refresh Token to Get New Access Token:")
	fmt.Println("===============================================")

	// Use the refresh token to get a new access token
	newTokenResult, err := tm.RefreshToken(jwtResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh token: %v", err)
	}

	fmt.Printf("✅ New Access Token: %s...\n", newTokenResult.Token[:50])
	fmt.Printf("✅ New Access Token Expires At: %s\n", newTokenResult.ExpiresAt.Format(time.RFC3339))

	// 3. Show Configuration Details
	fmt.Println("\n3. Refresh Configuration Details:")
	fmt.Println("=================================")
	refreshConfig := &tokeno.TokenRefreshConfig{
		RefreshThreshold:   30 * time.Minute,   // Refresh 30 minutes before expiry
		MaxRefreshAttempts: 5,                  // Allow 5 refresh attempts
		RefreshGracePeriod: 5 * time.Minute,    // 5 minute grace period
		RefreshTokenLength: 64,                 // 64 character refresh tokens
		RefreshTokenExpiry: 7 * 24 * time.Hour, // Refresh tokens valid for 7 days
	}
	fmt.Printf("✅ Refresh Threshold: %v\n", refreshConfig.RefreshThreshold)
	fmt.Printf("✅ Max Refresh Attempts: %d\n", refreshConfig.MaxRefreshAttempts)
	fmt.Printf("✅ Refresh Grace Period: %v\n", refreshConfig.RefreshGracePeriod)
	fmt.Printf("✅ Refresh Token Length: %d\n", refreshConfig.RefreshTokenLength)
	fmt.Printf("✅ Refresh Token Expiry: %v\n", refreshConfig.RefreshTokenExpiry)

	fmt.Println("\n✅ Example completed successfully!")
}
