package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno MaxRefreshAttempts Example ===")
	fmt.Println("Demonstrating refresh token attempt limiting")
	fmt.Println()

	// Create TokenManager with limited refresh attempts
	config := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3, // Allow only 3 refresh attempts
			RefreshTokenExpiry: 24 * time.Hour,
		},
	}

	tm := tokeno.NewTokenManager(config)

	// 1. Create initial token
	fmt.Println("1. Creating Initial Token:")
	fmt.Println("=========================")

	initialResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithClaim("role", "admin").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create initial token: %v", err)
	}

	fmt.Printf("✅ Access Token: %s...\n", initialResult.Token[:50])
	fmt.Printf("✅ Refresh Token: %s...\n", initialResult.RefreshToken[:50])
	fmt.Printf("✅ Max Refresh Attempts: %d\n", config.RefreshConfig.MaxRefreshAttempts)

	// 2. Demonstrate refresh attempts
	fmt.Println("\n2. Refresh Token Attempts:")
	fmt.Println("==========================")

	refreshToken := initialResult.RefreshToken
	successfulRefreshes := 0

	for i := 1; i <= 5; i++ { // Try 5 times (limit is 3)
		fmt.Printf("\nAttempt %d:\n", i)

		result, err := tm.RefreshToken(refreshToken)

		if err != nil {
			fmt.Printf("❌ Error: %v\n", err)
			break
		}

		successfulRefreshes++
		refreshToken = result.RefreshToken

		fmt.Printf("✅ Success! New access token: %s...\n", result.Token[:50])
		fmt.Printf("✅ New refresh token: %s...\n", result.RefreshToken[:50])
		fmt.Printf("✅ Attempts used: %d/%d\n", successfulRefreshes, config.RefreshConfig.MaxRefreshAttempts)
	}

	fmt.Printf("\n📊 Summary:\n")
	fmt.Printf("✅ Successful refreshes: %d\n", successfulRefreshes)
	fmt.Printf("✅ Max allowed: %d\n", config.RefreshConfig.MaxRefreshAttempts)
	fmt.Printf("✅ Limit respected: %t\n", successfulRefreshes <= config.RefreshConfig.MaxRefreshAttempts)

	// 3. Demonstrate unlimited attempts (MaxRefreshAttempts = 0)
	fmt.Println("\n3. Unlimited Refresh Attempts (MaxRefreshAttempts = 0):")
	fmt.Println("=====================================================")

	unlimitedConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 0, // 0 means unlimited
			RefreshTokenExpiry: 24 * time.Hour,
		},
	}

	unlimitedTM := tokeno.NewTokenManager(unlimitedConfig)

	unlimitedResult, err := unlimitedTM.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user456").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create unlimited token: %v", err)
	}

	fmt.Printf("✅ Created token with unlimited refresh attempts\n")
	fmt.Printf("✅ Access Token: %s...\n", unlimitedResult.Token[:50])

	// Try multiple refreshes with unlimited config
	unlimitedRefreshToken := unlimitedResult.RefreshToken
	unlimitedRefreshes := 0

	for i := 1; i <= 3; i++ {
		result, err := unlimitedTM.RefreshToken(unlimitedRefreshToken)
		if err != nil {
			fmt.Printf("❌ Unexpected error: %v\n", err)
			break
		}
		unlimitedRefreshes++
		unlimitedRefreshToken = result.RefreshToken
		fmt.Printf("✅ Unlimited refresh %d successful\n", i)
	}

	fmt.Printf("✅ Unlimited refreshes completed: %d\n", unlimitedRefreshes)

	// 4. Demonstrate negative MaxRefreshAttempts (no refreshes allowed)
	fmt.Println("\n4. No Refresh Attempts (MaxRefreshAttempts = -1):")
	fmt.Println("===============================================")

	noRefreshConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: -1, // Negative means no refreshes allowed
			RefreshTokenExpiry: 24 * time.Hour,
		},
	}

	noRefreshTM := tokeno.NewTokenManager(noRefreshConfig)

	noRefreshResult, err := noRefreshTM.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user789").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create no-refresh token: %v", err)
	}

	fmt.Printf("✅ Created token with no refresh attempts allowed\n")
	fmt.Printf("✅ Access Token: %s...\n", noRefreshResult.Token[:50])

	// Try to refresh - should fail immediately
	_, err = noRefreshTM.RefreshToken(noRefreshResult.RefreshToken)
	if err != nil {
		fmt.Printf("✅ Refresh correctly blocked: %v\n", err)
	} else {
		fmt.Printf("❌ Unexpected success - should have been blocked\n")
	}

	fmt.Println("\n✅ MaxRefreshAttempts example completed successfully!")
	fmt.Println("\n📝 Key Points:")
	fmt.Println("   • MaxRefreshAttempts > 0: Limited number of refresh attempts")
	fmt.Println("   • MaxRefreshAttempts = 0: Unlimited refresh attempts")
	fmt.Println("   • MaxRefreshAttempts < 0: No refresh attempts allowed")
	fmt.Println("   • Attempts counter is incremented with each refresh")
	fmt.Println("   • Once limit is reached, refresh token becomes invalid")
}
