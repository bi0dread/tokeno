package tokeno

import (
	"testing"
	"time"
)

func TestRefreshTokenExpiration(t *testing.T) {
	// Test with different refresh token expiration times
	testCases := []struct {
		name               string
		refreshTokenExpiry time.Duration
		expectedDuration   time.Duration
	}{
		{
			name:               "1 hour refresh token expiry",
			refreshTokenExpiry: 1 * time.Hour,
			expectedDuration:   1 * time.Hour,
		},
		{
			name:               "1 day refresh token expiry",
			refreshTokenExpiry: 24 * time.Hour,
			expectedDuration:   24 * time.Hour,
		},
		{
			name:               "1 week refresh token expiry",
			refreshTokenExpiry: 7 * 24 * time.Hour,
			expectedDuration:   7 * 24 * time.Hour,
		},
		{
			name:               "1 month refresh token expiry",
			refreshTokenExpiry: 30 * 24 * time.Hour,
			expectedDuration:   30 * 24 * time.Hour,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create TokenManager with specific refresh token expiry
			config := &TokenManagerConfig{
				JWTSecretKey: []byte("test-secret"),
				JWTMethod:    SigningMethodHS256,
				RefreshConfig: &TokenRefreshConfig{
					RefreshThreshold:   1 * time.Hour,
					MaxRefreshAttempts: 3,
					RefreshTokenLength: 32,
					RefreshTokenExpiry: tc.refreshTokenExpiry,
				},
			}

			tm := NewTokenManager(config)

			// Create JWT token with shorter access token expiry
			tokenResult, err := tm.NewToken().
				WithIssuer("test-issuer").
				WithSubject("user123").
				WithExpiration(time.Now().Add(30 * time.Minute)). // Shorter than refresh token
				CreateJWTWithHMAC(SigningMethodHS256)

			if err != nil {
				t.Fatalf("Failed to create JWT token: %v", err)
			}

			// Verify refresh token is present
			if tokenResult.RefreshToken == "" {
				t.Error("Expected refresh token to be present")
			}

			// Parse refresh token to check expiration
			refreshClaims, err := tm.ValidateJWTWithHMAC(tokenResult.RefreshToken, SigningMethodHS256)
			if err != nil {
				t.Fatalf("Failed to validate refresh token: %v", err)
			}

			// Calculate actual duration
			actualDuration := refreshClaims.ExpiresAt.Sub(refreshClaims.IssuedAt)

			// Allow for small time differences (within 1 second)
			expectedMin := tc.expectedDuration - time.Second
			expectedMax := tc.expectedDuration + time.Second

			if actualDuration < expectedMin || actualDuration > expectedMax {
				t.Errorf("Expected refresh token duration to be around %v, got %v", tc.expectedDuration, actualDuration)
			}

			// Verify refresh token has longer expiration than access token
			if refreshClaims.ExpiresAt.Before(tokenResult.ExpiresAt) {
				t.Error("Expected refresh token to have longer expiration than access token")
			}
		})
	}
}

func TestRefreshTokenExpirationValidation(t *testing.T) {
	// Create TokenManager with short refresh token expiry
	config := &TokenManagerConfig{
		JWTSecretKey: []byte("test-secret"),
		JWTMethod:    SigningMethodHS256,
		RefreshConfig: &TokenRefreshConfig{
			RefreshThreshold:   1 * time.Hour,
			MaxRefreshAttempts: 3,
			RefreshTokenLength: 32,
			RefreshTokenExpiry: 1 * time.Second, // 1 second expiry
		},
	}

	tm := NewTokenManager(config)

	// Create JWT token
	tokenResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("user123").
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Verify refresh token works initially
	_, err = tm.RefreshToken(tokenResult.RefreshToken)
	if err != nil {
		t.Errorf("Expected refresh token to work initially, got error: %v", err)
	}

	// Wait for refresh token to expire
	time.Sleep(2 * time.Second)

	// Verify expired refresh token is rejected
	_, err = tm.RefreshToken(tokenResult.RefreshToken)
	if err == nil {
		t.Error("Expected expired refresh token to be rejected")
	}

	// Check that the error indicates expiration
	if err != nil && !contains(err.Error(), "expired") {
		t.Errorf("Expected error to indicate expiration, got: %v", err)
	}
}

func TestRefreshTokenExpirationWithoutConfig(t *testing.T) {
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
		WithExpiration(time.Now().Add(1 * time.Hour)).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Verify no refresh token is generated
	if tokenResult.RefreshToken != "" {
		t.Error("Expected no refresh token when no refresh config")
	}
}

// Helper function to check if error message contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || (len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsSubstring(s, substr))))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
