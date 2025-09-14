package tokeno

import (
	"fmt"
	"testing"
	"time"
)

func TestRefreshTokenVerification(t *testing.T) {
	// Create TokenManager with refresh configuration
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,
			MaxRefreshAttempts: 5,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 24 * time.Hour,
		},
	}

	tm := NewTokenManager(config)

	// Create JWT token with refresh token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Test 1: Direct JWT Validation
	t.Run("Direct JWT Validation", func(t *testing.T) {
		claims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate refresh token: %v", err)
		}

		// Verify refresh token properties
		if claims.CustomClaims["token_type"] != "refresh" {
			t.Error("Expected token_type to be 'refresh'")
		}

		if attempts, ok := claims.CustomClaims["attempts"].(float64); !ok || attempts != 0 {
			t.Error("Expected attempts to be 0")
		}

		if _, ok := claims.CustomClaims["access_token"].(string); !ok {
			t.Error("Expected access_token to be present")
		}

		if claims.Issuer != "test-issuer" {
			t.Errorf("Expected issuer to be 'test-issuer', got %s", claims.Issuer)
		}

		if claims.Subject != "user123" {
			t.Errorf("Expected subject to be 'user123', got %s", claims.Subject)
		}
	})

	// Test 2: Auto-Detection Validation
	t.Run("Auto-Detection Validation", func(t *testing.T) {
		claims, err := tm.ValidateJWTToken(tokenResult.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to validate refresh token: %v", err)
		}

		if claims.CustomClaims["token_type"] != "refresh" {
			t.Error("Expected token_type to be 'refresh'")
		}
	})

	// Test 3: Token Type Detection + Validation
	t.Run("Token Type Detection + Validation", func(t *testing.T) {
		tokenType := DetectTokenType(tokenResult.RefreshToken)
		if tokenType != TokenTypeJWT {
			t.Errorf("Expected token type to be JWT, got %s", tokenType)
		}

		claims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate refresh token: %v", err)
		}

		if claims.CustomClaims["token_type"] != "refresh" {
			t.Error("Expected token_type to be 'refresh'")
		}
	})

	// Test 4: Opaque Refresh Token Verification
	t.Run("Opaque Refresh Token Verification", func(t *testing.T) {
		opaqueResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("user456").
			WithExpiration(time.Now().Add(1 * time.Hour)).
			CreateOpaqueWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create opaque token: %v", err)
		}

		claims, err := tm.ValidateOpaqueWithHMAC(opaqueResult.RefreshToken, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate opaque refresh token: %v", err)
		}

		if claims.CustomClaims["token_type"] != "refresh" {
			t.Error("Expected token_type to be 'refresh'")
		}

		if attempts, ok := claims.CustomClaims["attempts"].(float64); !ok || attempts != 0 {
			t.Error("Expected attempts to be 0")
		}
	})

	// Test 5: Error Handling
	t.Run("Error Handling", func(t *testing.T) {
		// Test with invalid token
		_, err := tm.ValidateJWTWithHMAC("invalid.token.here", SigningMethodHS256)
		if err == nil {
			t.Error("Expected invalid token to be rejected")
		}

		// Test with empty token
		_, err = tm.ValidateJWTWithHMAC("", SigningMethodHS256)
		if err == nil {
			t.Error("Expected empty token to be rejected")
		}
	})

	// Test 6: Expired Refresh Token
	t.Run("Expired Refresh Token", func(t *testing.T) {
		// Create TokenManager with very short refresh token expiry
		shortConfig := &TokenManagerConfig{
			JWTSecretKey: []byte("test-secret"),
			JWTMethod:    SigningMethodHS256,
			RefreshConfig: &TokenRefreshConfig{
				RefreshThreshold:   1 * time.Hour,
				MaxRefreshAttempts: 3,
				RefreshTokenLength: 32,
				RefreshTokenExpiry: 100 * time.Millisecond, // Very short expiry
			},
		}

		shortTM := NewTokenManager(shortConfig)
		shortResult, err := shortTM.NewToken().
			WithIssuer("test-issuer").
			WithSubject("testuser").
			WithExpiration(time.Now().Add(1 * time.Hour)).
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create short-lived token: %v", err)
		}

		// Wait for refresh token to expire
		time.Sleep(200 * time.Millisecond)

		_, err = shortTM.ValidateJWTWithHMAC(shortResult.RefreshToken, SigningMethodHS256)
		if err == nil {
			t.Error("Expected expired refresh token to be rejected")
		}

		// Check that the error indicates expiration
		if err != nil && !contains(err.Error(), "expired") {
			t.Errorf("Expected error to indicate expiration, got: %v", err)
		}
	})
}

func TestCompleteRefreshTokenVerification(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   30 * time.Minute,
			MaxRefreshAttempts: 5,
			RefreshTokenLength: 64,
			RefreshTokenExpiry: 24 * time.Hour,
		},
	}

	tm := NewTokenManager(config)

	// Create JWT token with refresh token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Test complete verification function
	isValid, claims, err := verifyRefreshToken(tm, tokenResult.RefreshToken)
	if err != nil {
		t.Fatalf("Verification failed: %v", err)
	}

	if !isValid {
		t.Error("Expected refresh token to be valid")
	}

	if claims.Issuer != "test-issuer" {
		t.Errorf("Expected issuer to be 'test-issuer', got %s", claims.Issuer)
	}

	if claims.Subject != "user123" {
		t.Errorf("Expected subject to be 'user123', got %s", claims.Subject)
	}

	if claims.CustomClaims["token_type"] != "refresh" {
		t.Error("Expected token_type to be 'refresh'")
	}

	// Test with invalid token
	_, _, err = verifyRefreshToken(tm, "invalid.token.here")
	if err == nil {
		t.Error("Expected invalid token to be rejected")
	}

	// Test with empty token
	_, _, err = verifyRefreshToken(tm, "")
	if err == nil {
		t.Error("Expected empty token to be rejected")
	}
}

// Complete refresh token verification function (same as in example)
func verifyRefreshToken(tm *TokenManager, refreshToken string) (bool, *TokenRequest, error) {
	// Detect token type
	tokenType := DetectTokenType(refreshToken)

	var claims *TokenRequest
	var err error

	// Validate based on token type
	switch tokenType {
	case TokenTypeJWT:
		claims, err = tm.ValidateJWTWithHMAC(refreshToken, SigningMethodHS256)
	case TokenTypeOpaque:
		claims, err = tm.ValidateOpaqueWithHMAC(refreshToken, SigningMethodHS256)
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
