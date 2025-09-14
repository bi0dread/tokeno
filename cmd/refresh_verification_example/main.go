package main

import (
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno Refresh Token Verification Methods ===")
	fmt.Println("Demonstrating all available methods to verify refresh tokens")
	fmt.Println()

	// Create TokenManager with refresh configuration
	config := &tokeno.TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    tokeno.SigningMethodHS256,
		RefreshConfig: &tokeno.TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,
			MaxRefreshAttempts: 5,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 24 * time.Hour, // 24 hours
		},
	}

	tm := tokeno.NewTokenManager(config)

	// Create a token with refresh token
	fmt.Println("1. Creating Access Token with Refresh Token:")
	fmt.Println("=============================================")

	tokenResult, err := tm.NewToken().
		WithIssuer("test-service").
		WithSubject("user123").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create token: %v", err)
	}

	fmt.Printf("✅ Access Token: %s...\n", tokenResult.Token[:30])
	fmt.Printf("✅ Refresh Token: %s...\n", tokenResult.RefreshToken[:30])
	fmt.Printf("✅ Access Token Expires: %s\n", tokenResult.ExpiresAt.Format(time.RFC3339))

	// Method 1: Direct JWT Validation (Recommended for JWT refresh tokens)
	fmt.Println("\n2. Method 1: Direct JWT Validation:")
	fmt.Println("====================================")

	refreshClaims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Refresh Token Valid: %t\n", err == nil)
	fmt.Printf("✅ Issuer: %s\n", refreshClaims.Issuer)
	fmt.Printf("✅ Subject: %s\n", refreshClaims.Subject)
	fmt.Printf("✅ Expires At: %s\n", refreshClaims.ExpiresAt.Format(time.RFC3339))
	fmt.Printf("✅ Token Type: %s\n", refreshClaims.CustomClaims["token_type"])
	fmt.Printf("✅ Attempts: %.0f\n", refreshClaims.CustomClaims["attempts"])
	fmt.Printf("✅ Has Access Token: %t\n", refreshClaims.CustomClaims["access_token"] != nil)

	// Method 2: Auto-Detection Validation
	fmt.Println("\n3. Method 2: Auto-Detection Validation:")
	fmt.Println("======================================")

	autoClaims, err := tm.ValidateJWTToken(tokenResult.RefreshToken)
	if err != nil {
		log.Fatalf("Failed to validate refresh token: %v", err)
	}

	fmt.Printf("✅ Auto-Detection Valid: %t\n", err == nil)
	fmt.Printf("✅ Issuer: %s\n", autoClaims.Issuer)
	fmt.Printf("✅ Subject: %s\n", autoClaims.Subject)
	fmt.Printf("✅ Token Type: %s\n", autoClaims.CustomClaims["token_type"])

	// Method 3: Token Type Detection + Validation
	fmt.Println("\n4. Method 3: Token Type Detection + Validation:")
	fmt.Println("===============================================")

	tokenType := tokeno.DetectTokenType(tokenResult.RefreshToken)
	fmt.Printf("✅ Detected Token Type: %s\n", tokenType)

	switch tokenType {
	case tokeno.TokenTypeJWT:
		detectedClaims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, tokeno.SigningMethodHS256)
		if err != nil {
			log.Fatalf("Failed to validate JWT refresh token: %v", err)
		}
		fmt.Printf("✅ JWT Validation Successful\n")
		fmt.Printf("✅ Token Type: %s\n", detectedClaims.CustomClaims["token_type"])
	case tokeno.TokenTypeOpaque:
		detectedClaims, err := tm.ValidateOpaqueWithHMAC(tokenResult.RefreshToken, tokeno.SigningMethodHS256)
		if err != nil {
			log.Fatalf("Failed to validate Opaque refresh token: %v", err)
		}
		fmt.Printf("✅ Opaque Validation Successful\n")
		fmt.Printf("✅ Token Type: %s\n", detectedClaims.CustomClaims["token_type"])
	default:
		fmt.Printf("❌ Unknown token type: %s\n", tokenType)
	}

	// Method 4: Verify Refresh Token Properties
	fmt.Println("\n5. Method 4: Verify Refresh Token Properties:")
	fmt.Println("=============================================")

	// Check if it's a valid refresh token
	if refreshClaims.CustomClaims["token_type"] == "refresh" {
		fmt.Println("✅ Valid refresh token type")
	} else {
		fmt.Println("❌ Invalid refresh token type")
	}

	// Check attempts
	if attempts, ok := refreshClaims.CustomClaims["attempts"].(float64); ok {
		fmt.Printf("✅ Refresh attempts: %.0f\n", attempts)
		if attempts >= 5 {
			fmt.Println("⚠️  Max refresh attempts reached")
		}
	}

	// Check if access token is embedded
	if accessToken, ok := refreshClaims.CustomClaims["access_token"].(string); ok {
		fmt.Printf("✅ Access token embedded: %s...\n", accessToken[:30])
	} else {
		fmt.Println("❌ No access token embedded")
	}

	// Check expiration
	if refreshClaims.ExpiresAt.After(time.Now()) {
		fmt.Println("✅ Refresh token not expired")
		fmt.Printf("✅ Expires in: %v\n", time.Until(refreshClaims.ExpiresAt))
	} else {
		fmt.Println("❌ Refresh token expired")
	}

	// Method 5: Test with Opaque Refresh Token
	fmt.Println("\n6. Method 5: Opaque Refresh Token Verification:")
	fmt.Println("===============================================")

	// Create Opaque token with refresh
	opaqueResult, err := tm.NewToken().
		WithIssuer("test-service").
		WithSubject("user456").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create opaque token: %v", err)
	}

	fmt.Printf("✅ Opaque Access Token: %s...\n", opaqueResult.Token[:30])
	fmt.Printf("✅ Opaque Refresh Token: %s...\n", opaqueResult.RefreshToken[:30])

	// Verify Opaque refresh token
	opaqueRefreshClaims, err := tm.ValidateOpaqueWithHMAC(opaqueResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate opaque refresh token: %v", err)
	}

	fmt.Printf("✅ Opaque Refresh Token Valid: %t\n", err == nil)
	fmt.Printf("✅ Token Type: %s\n", opaqueRefreshClaims.CustomClaims["token_type"])
	fmt.Printf("✅ Attempts: %.0f\n", opaqueRefreshClaims.CustomClaims["attempts"])

	// Method 6: Error Handling Examples
	fmt.Println("\n7. Method 6: Error Handling Examples:")
	fmt.Println("=====================================")

	// Test with invalid token
	_, err = tm.ValidateJWTWithHMAC("invalid.token.here", tokeno.SigningMethodHS256)
	if err != nil {
		fmt.Printf("✅ Invalid token correctly rejected: %v\n", err)
	}

	// Test with expired token (create one with very short expiry)
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
	shortResult, err := shortTM.NewToken().
		WithIssuer("test-service").
		WithSubject("testuser").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create short-lived token: %v", err)
	}

	// Wait for refresh token to expire
	time.Sleep(200 * time.Millisecond)

	_, err = shortTM.ValidateJWTWithHMAC(shortResult.RefreshToken, tokeno.SigningMethodHS256)
	if err != nil {
		fmt.Printf("✅ Expired refresh token correctly rejected: %v\n", err)
	}

	// Method 7: Complete Verification Function
	fmt.Println("\n8. Method 7: Complete Verification Function:")
	fmt.Println("=============================================")

	// Example of a complete refresh token verification function
	isValid, claims, err := verifyRefreshToken(tm, tokenResult.RefreshToken)
	if err != nil {
		fmt.Printf("❌ Verification failed: %v\n", err)
	} else {
		fmt.Printf("✅ Refresh token is valid: %t\n", isValid)
		fmt.Printf("✅ Issuer: %s\n", claims.Issuer)
		fmt.Printf("✅ Subject: %s\n", claims.Subject)
		fmt.Printf("✅ Token Type: %s\n", claims.CustomClaims["token_type"])
		fmt.Printf("✅ Attempts: %.0f\n", claims.CustomClaims["attempts"])
	}

	fmt.Println("\n=== Refresh Token Verification Methods Complete ===")
}

// Complete refresh token verification function
func verifyRefreshToken(tm *tokeno.TokenManager, refreshToken string) (bool, *tokeno.TokenRequest, error) {
	// Detect token type
	tokenType := tokeno.DetectTokenType(refreshToken)

	var claims *tokeno.TokenRequest
	var err error

	// Validate based on token type
	switch tokenType {
	case tokeno.TokenTypeJWT:
		claims, err = tm.ValidateJWTWithHMAC(refreshToken, tokeno.SigningMethodHS256)
	case tokeno.TokenTypeOpaque:
		claims, err = tm.ValidateOpaqueWithHMAC(refreshToken, tokeno.SigningMethodHS256)
	default:
		return false, nil, fmt.Errorf("unknown token type: %s", tokenType)
	}

	if err != nil {
		return false, nil, fmt.Errorf("token validation failed: %w", err)
	}

	// Check if it's a refresh token
	if tokenType, ok := claims.CustomClaims["token_type"]; !ok || tokenType != "refresh" {
		return false, nil, fmt.Errorf("not a refresh token")
	}

	// Check if not expired
	if claims.ExpiresAt.Before(time.Now()) {
		return false, nil, fmt.Errorf("refresh token expired")
	}

	// Check attempts (optional - depends on your requirements)
	if attempts, ok := claims.CustomClaims["attempts"].(float64); ok {
		if attempts >= 5 { // Assuming max 5 attempts
			return false, nil, fmt.Errorf("max refresh attempts exceeded")
		}
	}

	// Check if access token is embedded
	if _, ok := claims.CustomClaims["access_token"].(string); !ok {
		return false, nil, fmt.Errorf("no access token embedded")
	}

	return true, claims, nil
}
