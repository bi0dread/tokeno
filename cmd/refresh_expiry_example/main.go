package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno Refresh Token Expiration Configuration ===")
	fmt.Println("Demonstrating how to set different refresh token expiration times")
	fmt.Println()

	// 1. Short Refresh Token Expiration (1 hour)
	fmt.Println("1. Short Refresh Token Expiration (1 hour):")
	fmt.Println("===========================================")

	shortConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 1 * time.Hour, // ✅ 1 hour refresh token expiry
		},
	}

	shortTM := tokeno.NewTokenManager(shortConfig)

	shortResult, err := shortTM.NewToken().
		WithIssuer("test-service").
		WithSubject("user123").
		WithExpiration(time.Now().Add(30 * time.Minute)). // Access token expires in 30 minutes
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Access Token Expires At: %s\n", shortResult.ExpiresAt.Format(time.RFC3339))

	// Parse refresh token to see its expiration
	refreshClaims, err := shortTM.ValidateJWTWithHMAC(shortResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Expires At: %s\n", refreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Duration: %v\n", refreshClaims.ExpiresAt.Sub(refreshClaims.IssuedAt))

	// 2. Medium Refresh Token Expiration (1 day)
	fmt.Println("\n2. Medium Refresh Token Expiration (1 day):")
	fmt.Println("==========================================")

	mediumConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 5,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 24 * time.Hour, // ✅ 1 day refresh token expiry
		},
	}

	mediumTM := tokeno.NewTokenManager(mediumConfig)

	mediumResult, err := mediumTM.NewToken().
		WithIssuer("test-service").
		WithSubject("user456").
		WithExpiration(time.Now().Add(2 * time.Hour)). // Access token expires in 2 hours
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Access Token Expires At: %s\n", mediumResult.ExpiresAt.Format(time.RFC3339))

	// Parse refresh token to see its expiration
	mediumRefreshClaims, err := mediumTM.ValidateJWTWithHMAC(mediumResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Expires At: %s\n", mediumRefreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Duration: %v\n", mediumRefreshClaims.ExpiresAt.Sub(mediumRefreshClaims.IssuedAt))

	// 3. Long Refresh Token Expiration (30 days)
	fmt.Println("\n3. Long Refresh Token Expiration (30 days):")
	fmt.Println("===========================================")

	longConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   2 * time.Hour,
			MaxRefreshAttempts: 10,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 30 * 24 * time.Hour, // ✅ 30 days refresh token expiry
		},
	}

	longTM := tokeno.NewTokenManager(longConfig)

	longResult, err := longTM.NewToken().
		WithIssuer("test-service").
		WithSubject("user789").
		WithExpiration(time.Now().Add(4 * time.Hour)). // Access token expires in 4 hours
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Access Token Expires At: %s\n", longResult.ExpiresAt.Format(time.RFC3339))

	// Parse refresh token to see its expiration
	longRefreshClaims, err := longTM.ValidateJWTWithHMAC(longResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Expires At: %s\n", longRefreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Duration: %v\n", longRefreshClaims.ExpiresAt.Sub(longRefreshClaims.IssuedAt))

	// 4. Custom Refresh Token Expiration (2 weeks)
	fmt.Println("\n4. Custom Refresh Token Expiration (2 weeks):")
	fmt.Println("=============================================")

	customConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 7,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 14 * 24 * time.Hour, // ✅ 2 weeks refresh token expiry
		},
	}

	customTM := tokeno.NewTokenManager(customConfig)

	customResult, err := customTM.NewToken().
		WithIssuer("test-service").
		WithSubject("user999").
		WithExpiration(time.Now().Add(1 * time.Hour)). // Access token expires in 1 hour
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Access Token Expires At: %s\n", customResult.ExpiresAt.Format(time.RFC3339))

	// Parse refresh token to see its expiration
	customRefreshClaims, err := customTM.ValidateJWTWithHMAC(customResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Expires At: %s\n", customRefreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Duration: %v\n", customRefreshClaims.ExpiresAt.Sub(customRefreshClaims.IssuedAt))

	// 5. Demonstrate Refresh Token Expiration Validation
	fmt.Println("\n5. Refresh Token Expiration Validation:")
	fmt.Println("======================================")

	// Create a very short-lived refresh token for testing
	veryShortConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Minute,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 100 * time.Millisecond, // ✅ Very short expiry for testing
		},
	}

	veryShortTM := tokeno.NewTokenManager(veryShortConfig)

	veryShortResult, err := veryShortTM.NewToken().
		WithIssuer("test-service").
		WithSubject("testuser").
		WithExpiration(time.Now().Add(1 * time.Minute)).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Created token with very short refresh expiry (100ms)\n")
	fmt.Printf("✅ Access Token: %s...\n", veryShortResult.Token[:30])
	fmt.Printf("✅ Refresh Token: %s...\n", veryShortResult.RefreshToken[:30])

	// Wait for refresh token to expire
	fmt.Println("⏳ Waiting for refresh token to expire...")
	time.Sleep(200 * time.Millisecond)

	// Try to use expired refresh token
	_, err = veryShortTM.RefreshToken(veryShortResult.RefreshToken)
	if err != nil {
		fmt.Printf("✅ Expired refresh token correctly rejected: %v\n", err)
	} else {
		fmt.Println("❌ ERROR: Expired refresh token should have been rejected!")
	}

	// 6. Configuration Summary
	fmt.Println("\n6. Refresh Token Expiration Configuration Summary:")
	fmt.Println("=================================================")
	fmt.Println("✅ RefreshTokenExpiry field in TokenRefreshConfig controls refresh token lifetime")
	fmt.Println("✅ Can be set to any time.Duration value:")
	fmt.Println("   - 1 * time.Hour        (1 hour)")
	fmt.Println("   - 24 * time.Hour       (1 day)")
	fmt.Println("   - 7 * 24 * time.Hour   (1 week)")
	fmt.Println("   - 30 * 24 * time.Hour  (1 month)")
	fmt.Println("   - 365 * 24 * time.Hour (1 year)")
	fmt.Println("✅ Refresh tokens automatically expire after the specified duration")
	fmt.Println("✅ Expired refresh tokens are rejected during refresh attempts")
	fmt.Println("✅ No cleanup needed - expiration is handled automatically")

	fmt.Println("\n=== Refresh Token Expiration Example Complete ===")
}
