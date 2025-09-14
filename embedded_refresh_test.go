package tokeno

import (
	"testing"
	"time"
)

func TestEmbeddedRefreshJWT(t *testing.T) {
	// Create TokenManager with refresh config
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 32,
			RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		},
	}

	tm := NewTokenManager(config)

	// Create JWT token with embedded refresh token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithClaim("role", "admin").
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Verify both access token and refresh token are present
	if tokenResult.Token == "" {
		t.Error("Expected access token to be present")
	}

	if tokenResult.RefreshToken == "" {
		t.Error("Expected refresh token to be present")
	}

	if tokenResult.Type != TokenTypeJWT {
		t.Errorf("Expected token type to be JWT, got %s", tokenResult.Type)
	}

	// Verify refresh token is a valid JWT
	refreshClaims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	// Verify refresh token contains access token
	if accessToken, ok := refreshClaims.CustomClaims["access_token"].(string); !ok || accessToken != tokenResult.Token {
		t.Error("Expected refresh token to contain access token")
	}

	// Verify refresh token has correct type
	if tokenType, ok := refreshClaims.CustomClaims["token_type"].(string); !ok || tokenType != "refresh" {
		t.Error("Expected refresh token to have token_type 'refresh'")
	}

	// Verify refresh token has longer expiration
	if refreshClaims.ExpiresAt.Before(tokenResult.ExpiresAt) {
		t.Error("Expected refresh token to have longer expiration than access token")
	}

	// Verify attempts field (JSON unmarshaling converts numbers to float64)
	if attempts, ok := refreshClaims.CustomClaims["attempts"].(float64); !ok || int(attempts) != 0 {
		t.Error("Expected refresh token to have attempts field starting at 0")
	}
}

func TestEmbeddedRefreshOpaque(t *testing.T) {
	// Create TokenManager with refresh config
	config := &TokenManagerConfig{
		OpaqueSecretKey: []byte("test-opaque-secret"),
		OpaqueMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 32,
			RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		},
	}

	tm := NewTokenManager(config)

	// Create Opaque token with embedded refresh token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user456").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithClaim("role", "user").
		CreateOpaqueWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create Opaque token: %v", err)
	}

	// Verify both access token and refresh token are present
	if tokenResult.Token == "" {
		t.Error("Expected access token to be present")
	}

	if tokenResult.RefreshToken == "" {
		t.Error("Expected refresh token to be present")
	}

	if tokenResult.Type != TokenTypeOpaque {
		t.Errorf("Expected token type to be Opaque, got %s", tokenResult.Type)
	}

	// Verify refresh token is a valid Opaque token
	refreshClaims, err := tm.ValidateOpaqueWithHMAC(tokenResult.RefreshToken, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate refresh token: %v", err)
	}

	// Verify refresh token contains access token
	if accessToken, ok := refreshClaims.CustomClaims["access_token"].(string); !ok || accessToken != tokenResult.Token {
		t.Error("Expected refresh token to contain access token")
	}

	// Verify refresh token has correct type
	if tokenType, ok := refreshClaims.CustomClaims["token_type"].(string); !ok || tokenType != "refresh" {
		t.Error("Expected refresh token to have token_type 'refresh'")
	}

	// Verify refresh token has longer expiration
	if refreshClaims.ExpiresAt.Before(tokenResult.ExpiresAt) {
		t.Error("Expected refresh token to have longer expiration than access token")
	}
}

func TestEmbeddedRefreshFlow(t *testing.T) {
	// Create TokenManager with refresh config
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 32,
			RefreshTokenExpiry: 7 * 24 * time.Hour,
		},
	}

	tm := NewTokenManager(config)

	// Create initial token
	originalResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithClaim("role", "admin").
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create initial token: %v", err)
	}

	// Refresh the token
	refreshedResult, err := tm.RefreshToken(originalResult.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	// Verify new access token is different
	if refreshedResult.Token == originalResult.Token {
		t.Error("Expected refreshed token to be different from original")
	}

	// Verify new refresh token is different
	if refreshedResult.RefreshToken == originalResult.RefreshToken {
		t.Error("Expected new refresh token to be different from original")
	}

	// Verify the refreshed token is valid
	validated, err := tm.ValidateJWTWithHMAC(refreshedResult.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate refreshed token: %v", err)
	}

	if validated.Subject != "user123" {
		t.Errorf("Expected subject to be user123, got %s", validated.Subject)
	}

	// Verify refreshed claim is present
	if refreshed, ok := validated.CustomClaims["refreshed"]; !ok || refreshed != true {
		t.Error("Expected 'refreshed' claim to be true")
	}
}

func TestEmbeddedRefreshWithoutConfig(t *testing.T) {
	// Create TokenManager without refresh config
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		// No RefreshConfig
	}

	tm := NewTokenManager(config)

	// Create JWT token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Verify access token is present but refresh token is empty
	if tokenResult.Token == "" {
		t.Error("Expected access token to be present")
	}

	if tokenResult.RefreshToken != "" {
		t.Error("Expected refresh token to be empty when no refresh config")
	}
}
