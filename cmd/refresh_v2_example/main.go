package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno Refresh Token V2 Example ===")
	fmt.Println("Auto-generated refresh tokens with access token linking")
	fmt.Println()

	// Create TokenManager with refresh configuration
	config := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("your-jwt-secret-key"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,   // Refresh 30 minutes before expiry
			MaxRefreshAttempts: 5,                  // Allow 5 refresh attempts
			RefreshTokenLength: 64,                 // 64 character refresh tokens
			RefreshTokenExpiry: 7 * 24 * time.Hour, // Refresh tokens valid for 7 days
		},
	}

	tm := tokeno.NewTokenManager(config)

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

	fmt.Printf("✅ JWT Token: %s...\n", jwtResult.Token[:50])
	fmt.Printf("✅ Refresh Token: %s...\n", jwtResult.RefreshToken[:20])
	fmt.Printf("✅ Expires At: %s\n", jwtResult.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Token Type: %s\n", jwtResult.Type)

	// 2. Get Refresh Token Information
	fmt.Println("\n2. Refresh Token Information:")
	fmt.Println("============================")

	refreshInfo, err := tm.GetRefreshTokenInfo(jwtResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to get refresh token info: %v", err)
	}

	fmt.Printf("✅ Refresh Token: %s...\n", refreshInfo.Token[:50])
	fmt.Printf("✅ User ID: %s\n", refreshInfo.UserID)
	fmt.Printf("✅ Expire Time: %s\n", refreshInfo.ExpireTime.Format(time.RFC3339))
	fmt.Printf("✅ Attempts: %d\n", refreshInfo.Attempts)
	fmt.Printf("✅ Created At: %s\n", refreshInfo.CreatedAt.Format(time.RFC3339))

	// 3. Create Opaque Token with Auto-Generated Refresh Token
	fmt.Println("\n3. Creating Opaque Token with Auto-Generated Refresh Token:")
	fmt.Println("===========================================================")

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

	fmt.Printf("✅ Opaque Token: %s...\n", opaqueResult.Token[:50])
	fmt.Printf("✅ Refresh Token: %s...\n", opaqueResult.RefreshToken[:20])
	fmt.Printf("✅ Expires At: %s\n", opaqueResult.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Token Type: %s\n", opaqueResult.Type)

	// 4. Refresh JWT Token
	fmt.Println("\n4. Refreshing JWT Token:")
	fmt.Println("=======================")

	refreshedJWT, err := tm.RefreshToken(jwtResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh JWT token: %v", err)
	}

	fmt.Printf("✅ New JWT Token: %s...\n", refreshedJWT.Token[:50])
	fmt.Printf("✅ New Refresh Token: %s...\n", refreshedJWT.RefreshToken[:20])
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

	// 5. Refresh Opaque Token
	fmt.Println("\n5. Refreshing Opaque Token:")
	fmt.Println("===========================")

	refreshedOpaque, err := tm.RefreshToken(opaqueResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to refresh Opaque token: %v", err)
	}

	fmt.Printf("✅ New Opaque Token: %s...\n", refreshedOpaque.Token[:50])
	fmt.Printf("✅ New Refresh Token: %s...\n", refreshedOpaque.RefreshToken[:20])
	fmt.Printf("✅ New Expires At: %s\n", refreshedOpaque.ExpiresAt.Format(time.RFC3339))

	// Validate the refreshed opaque token
	validatedOpaque, err := tm.ValidateOpaqueWithHMAC(refreshedOpaque.Token, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refreshed Opaque: %v", err)
	}

	fmt.Printf("✅ Validated Subject: %s\n", validatedOpaque.Subject)
	fmt.Printf("✅ Validated Department: %s\n", validatedOpaque.CustomClaims["department"])

	// 6. Demonstrate Token Revocation
	fmt.Println("\n6. Token Revocation:")
	fmt.Println("===================")

	// Revoke specific refresh token
	err = tm.RevokeRefreshToken(refreshedJWT.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to revoke refresh token: %v", err)
	}
	fmt.Println("✅ Revoked specific refresh token")

	// Try to use revoked token
	_, err = tm.RefreshToken(refreshedJWT.RefreshToken)
	if err != nil {
		fmt.Printf("✅ Revoked token correctly rejected: %v\n", err)
	}

	// 7. Demonstrate User Token Revocation
	fmt.Println("\n7. User Token Revocation:")
	fmt.Println("========================")

	// Create multiple tokens for the same user
	user1Token1, _ := tm.NewToken().
		WithSubject("user789").
		WithIssuer("test").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	user1Token2, _ := tm.NewToken().
		WithSubject("user789").
		WithIssuer("test").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	fmt.Printf("✅ Created 2 tokens for user789\n")
	fmt.Printf("   Token 1 refresh: %s...\n", user1Token1.RefreshToken[:20])
	fmt.Printf("   Token 2 refresh: %s...\n", user1Token2.RefreshToken[:20])

	// Revoke all tokens for user789
	err = tm.RevokeUserRefreshTokens("user789")
	if err != nil {
		log.Fatalf("Failed to revoke user tokens: %v", err)
	}
	fmt.Println("✅ Revoked all tokens for user789")

	// Verify tokens are revoked
	_, err = tm.GetRefreshTokenInfo(user1Token1.RefreshToken)
	if err != nil {
		fmt.Println("✅ User1 Token1 correctly revoked")
	}

	_, err = tm.GetRefreshTokenInfo(user1Token2.RefreshToken)
	if err != nil {
		fmt.Println("✅ User1 Token2 correctly revoked")
	}

	// 8. Demonstrate Cleanup
	fmt.Println("\n8. Cleanup Expired Tokens:")
	fmt.Println("=========================")

	// Create a token manager with very short refresh token expiry
	shortConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 32,
			RefreshTokenExpiry: 100 * time.Millisecond, // Very short expiry
		},
	}

	shortTM := tokeno.NewTokenManager(shortConfig)

	// Create a token that will expire quickly
	shortToken, err := shortTM.NewToken().
		WithSubject("testuser").
		WithIssuer("test").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create short-lived token: %v", err)
	}

	fmt.Printf("✅ Created short-lived token: %s...\n", shortToken.RefreshToken[:20])

	// Wait for it to expire
	fmt.Println("⏳ Waiting for token to expire...")
	time.Sleep(200 * time.Millisecond)

	// Cleanup expired tokens
	cleaned := shortTM.CleanupExpiredRefreshTokens()
	fmt.Printf("✅ Cleaned up %d expired refresh tokens\n", cleaned)

	// Verify token is gone
	_, err = shortTM.GetRefreshTokenInfo(shortToken.RefreshToken)
	if err != nil {
		fmt.Println("✅ Short-lived token successfully cleaned up")
	}

	fmt.Println("\n=== Refresh Token V2 Example Complete ===")
	fmt.Println("Key Features Demonstrated:")
	fmt.Println("• Auto-generated refresh tokens for both JWT and Opaque tokens")
	fmt.Println("• Refresh tokens linked to specific access tokens")
	fmt.Println("• Automatic refresh token generation on token creation")
	fmt.Println("• Token refresh with new access and refresh tokens")
	fmt.Println("• Individual and user-level token revocation")
	fmt.Println("• Automatic cleanup of expired tokens")
}
