package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno Embedded Refresh Token Example ===")
	fmt.Println("Refresh tokens embedded as separate JWT/Opaque tokens with different expiration")
	fmt.Println()

	// Create TokenManager with refresh configuration
	config := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("your-jwt-secret-key"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,   // Refresh 30 minutes before expiry
			MaxRefreshAttempts: 5,                  // Allow 5 refresh attempts
			RefreshTokenLength: 64,                 // Not used in embedded approach
			RefreshTokenExpiry: 7 * 24 * time.Hour, // Refresh tokens valid for 7 days
		},
	}

	tm := tokeno.NewTokenManager(config)

	// 1. Create JWT Token with Embedded Refresh Token
	fmt.Println("1. Creating JWT Token with Embedded Refresh Token:")
	fmt.Println("==================================================")

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

	// 2. Inspect the Embedded Refresh Token
	fmt.Println("\n2. Inspecting Embedded Refresh Token:")
	fmt.Println("====================================")

	// Parse the refresh token to see its contents
	refreshClaims, err := tm.ValidateJWTWithHMAC(jwtResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Subject: %s\n", refreshClaims.Subject)
	fmt.Printf("✅ Refresh Token Expires At: %s\n", refreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Type: %s\n", refreshClaims.CustomClaims["token_type"])
	fmt.Printf("✅ Access Token Embedded: %s...\n", refreshClaims.CustomClaims["access_token"].(string)[:50])
	fmt.Printf("✅ Attempts: %.0f\n", refreshClaims.CustomClaims["attempts"].(float64))
	fmt.Printf("✅ Original Claims Preserved: role=%s\n", refreshClaims.CustomClaims["role"])

	// 3. Create Opaque Token with Embedded Refresh Token
	fmt.Println("\n3. Creating Opaque Token with Embedded Refresh Token:")
	fmt.Println("=====================================================")

	opaqueResult, err := tm.NewToken().
		WithIssuer("tokeno-service").
		WithSubject("user456").
		WithAudience("api-clients").
		WithExpiration(time.Now().Add(2*time.Hour)).
		WithClaim("role", "user").
		WithClaim("department", "engineering").
		CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create Opaque token: %v", err)
	}

	fmt.Printf("✅ Opaque Access Token: %s...\n", opaqueResult.Token[:50])
	fmt.Printf("✅ Opaque Refresh Token: %s...\n", opaqueResult.RefreshToken[:50])
	fmt.Printf("✅ Access Token Expires At: %s\n", opaqueResult.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Token Type: %s\n", opaqueResult.Type)

	// 4. Inspect the Embedded Opaque Refresh Token
	fmt.Println("\n4. Inspecting Embedded Opaque Refresh Token:")
	fmt.Println("===========================================")

	// Parse the opaque refresh token
	opaqueRefreshClaims, err := tm.ValidateOpaqueWithHMAC(opaqueResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate opaque refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Subject: %s\n", opaqueRefreshClaims.Subject)
	fmt.Printf("✅ Refresh Token Expires At: %s\n", opaqueRefreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Refresh Token Type: %s\n", opaqueRefreshClaims.CustomClaims["token_type"])
	fmt.Printf("✅ Access Token Embedded: %s...\n", opaqueRefreshClaims.CustomClaims["access_token"].(string)[:50])
	fmt.Printf("✅ Attempts: %.0f\n", opaqueRefreshClaims.CustomClaims["attempts"].(float64))
	fmt.Printf("✅ Original Claims Preserved: department=%s\n", opaqueRefreshClaims.CustomClaims["department"])

	// 5. Refresh JWT Token
	fmt.Println("\n5. Refreshing JWT Token:")
	fmt.Println("=======================")

	refreshedJWT, err := tm.RefreshToken(jwtResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh JWT token: %v", err)
	}

	fmt.Printf("✅ New JWT Access Token: %s...\n", refreshedJWT.Token[:50])
	fmt.Printf("✅ New JWT Refresh Token: %s...\n", refreshedJWT.RefreshToken[:50])
	fmt.Printf("✅ New Expires At: %s\n", refreshedJWT.ExpiresAt.Format(time.RFC3339))

	// Validate the refreshed token
	validatedJWT, err := tm.ValidateJWTWithHMAC(refreshedJWT.Token, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refreshed JWT: %v", err)
	}

	fmt.Printf("✅ Validated Subject: %s\n", validatedJWT.Subject)
	fmt.Printf("✅ Validated Role: %s\n", validatedJWT.CustomClaims["role"])
	if refreshed, ok := validatedJWT.CustomClaims["refreshed"]; ok {
		fmt.Printf("✅ Refreshed Claim: %t\n", refreshed)
	}

	// 6. Refresh Opaque Token
	fmt.Println("\n6. Refreshing Opaque Token:")
	fmt.Println("===========================")

	refreshedOpaque, err := tm.RefreshToken(opaqueResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh Opaque token: %v", err)
	}

	fmt.Printf("✅ New Opaque Access Token: %s...\n", refreshedOpaque.Token[:50])
	fmt.Printf("✅ New Opaque Refresh Token: %s...\n", refreshedOpaque.RefreshToken[:50])
	fmt.Printf("✅ New Expires At: %s\n", refreshedOpaque.ExpiresAt.Format(time.RFC3339))

	// Validate the refreshed opaque token
	validatedOpaque, err := tm.ValidateOpaqueWithHMAC(refreshedOpaque.Token, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refreshed Opaque: %v", err)
	}

	fmt.Printf("✅ Validated Subject: %s\n", validatedOpaque.Subject)
	fmt.Printf("✅ Validated Department: %s\n", validatedOpaque.CustomClaims["department"])

	// 7. Demonstrate Token Without Refresh Config
	fmt.Println("\n7. Token Without Refresh Config:")
	fmt.Println("===============================")

	// Create TokenManager without refresh config
	noRefreshConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		// No RefreshConfig
	}

	noRefreshTM := tokeno.NewTokenManager(noRefreshConfig)

	// Create JWT token without refresh
	noRefreshResult, err := noRefreshTM.NewToken().
		WithSubject("user789").
		WithIssuer("test").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token without refresh: %v", err)
	}

	fmt.Printf("✅ Access Token: %s...\n", noRefreshResult.Token[:50])
	fmt.Printf("✅ Refresh Token: '%s' (empty)\n", noRefreshResult.RefreshToken)

	// 8. Demonstrate Refresh Token Structure
	fmt.Println("\n8. Refresh Token Structure Analysis:")
	fmt.Println("===================================")

	// Show the structure of the embedded refresh token
	fmt.Println("JWT Refresh Token Structure:")
	fmt.Printf("  - Header: Contains algorithm (HS256) and type (JWT)\n")
	fmt.Printf("  - Payload: Contains claims including:\n")
	fmt.Printf("    * access_token: The original access token\n")
	fmt.Printf("    * token_type: 'refresh'\n")
	fmt.Printf("    * attempts: Number of refresh attempts\n")
	fmt.Printf("    * All original claims (role, permissions, etc.)\n")
	fmt.Printf("    * Longer expiration time than access token\n")
	fmt.Printf("  - Signature: HMAC signature for integrity\n")

	fmt.Println("\nOpaque Refresh Token Structure:")
	fmt.Printf("  - Base64 encoded JSON containing:\n")
	fmt.Printf("    * TokenRequest with all claims\n")
	fmt.Printf("    * access_token: The original access token\n")
	fmt.Printf("    * token_type: 'refresh'\n")
	fmt.Printf("    * attempts: Number of refresh attempts\n")
	fmt.Printf("    * Longer expiration time than access token\n")
	fmt.Printf("  - HMAC signature for integrity\n")

	fmt.Println("\n=== Embedded Refresh Token Example Complete ===")
	fmt.Println("Key Features Demonstrated:")
	fmt.Println("• Refresh tokens are embedded as separate JWT/Opaque tokens")
	fmt.Println("• Refresh tokens contain the original access token")
	fmt.Println("• Refresh tokens have different (longer) expiration times")
	fmt.Println("• No separate storage needed - everything is in the tokens")
	fmt.Println("• Automatic refresh token generation on token creation")
	fmt.Println("• Token refresh with new access and refresh tokens")
	fmt.Println("• Works with both JWT and Opaque token types")
}
