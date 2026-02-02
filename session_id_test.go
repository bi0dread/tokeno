package tokeno

import (
	"testing"
	"time"
)

func TestSessionIDFunctionality(t *testing.T) {
	// Create a token manager
	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-secret-key"),
		JWTMethod:         SigningMethodHS256,
		DefaultExpiration: 1 * time.Hour,
	}

	tm := NewTokenManager(config)

	// Test 1: Create token without session_id - should generate one automatically
	t.Run("Auto-generate session_id for new token", func(t *testing.T) {
		tokenResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Validate the token to extract claims
		claims, err := tm.ValidateJWTWithHMAC(tokenResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		// Check that session_id was generated
		if claims.SessionID == "" {
			t.Error("Expected session_id to be generated, but it was empty")
		}

		t.Logf("Generated session_id: %s", claims.SessionID)
	})

	// Test 2: Create token with explicit session_id
	t.Run("Use explicit session_id", func(t *testing.T) {
		expectedSessionID := "custom-session-123"

		tokenResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			WithSessionID(expectedSessionID).
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Validate the token to extract claims
		claims, err := tm.ValidateJWTWithHMAC(tokenResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		// Check that session_id matches the expected value
		if claims.SessionID != expectedSessionID {
			t.Errorf("Expected session_id %s, got %s", expectedSessionID, claims.SessionID)
		}
	})

	// Test 3: Test session_id preservation through refresh tokens
	t.Run("Session ID preservation through refresh", func(t *testing.T) {
		// Set up refresh configuration
		refreshConfig := &TokenRefreshConfig{
			RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
			MaxRefreshAttempts: 5,
		}
		tm.config.RefreshConfig = refreshConfig

		// Create initial token with session_id
		originalSessionID := "original-session-456"
		tokenResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			WithSessionID(originalSessionID).
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create initial token: %v", err)
		}

		// Verify initial token has the session_id
		initialClaims, err := tm.ValidateJWTWithHMAC(tokenResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate initial token: %v", err)
		}

		if initialClaims.SessionID != originalSessionID {
			t.Errorf("Initial token session_id mismatch: expected %s, got %s", originalSessionID, initialClaims.SessionID)
		}

		// Use refresh token to get new access token
		refreshedResult, err := tm.RefreshToken(tokenResult.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to refresh token: %v", err)
		}

		// Verify refreshed token preserves the session_id
		refreshedClaims, err := tm.ValidateJWTWithHMAC(refreshedResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate refreshed token: %v", err)
		}

		if refreshedClaims.SessionID != originalSessionID {
			t.Errorf("Refreshed token session_id mismatch: expected %s, got %s", originalSessionID, refreshedClaims.SessionID)
		}

		t.Logf("Session ID preserved through refresh: %s", refreshedClaims.SessionID)
	})

	// Test 4: Test session_id from WithClaim takes precedence
	t.Run("Session ID from WithClaim takes precedence", func(t *testing.T) {
		expectedSessionID := "claim-session-789"

		tokenResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			WithClaim("session_id", expectedSessionID).
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Validate the token to extract claims
		claims, err := tm.ValidateJWTWithHMAC(tokenResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		// Check that session_id from WithClaim was used
		if claims.SessionID != expectedSessionID {
			t.Errorf("Expected session_id from WithClaim %s, got %s", expectedSessionID, claims.SessionID)
		}

		t.Logf("Session ID from WithClaim: %s", claims.SessionID)
	})

	// Test 5: Test that WithSessionID takes precedence over WithClaim
	t.Run("WithSessionID takes precedence over WithClaim", func(t *testing.T) {
		expectedSessionID := "session-id-precedence"
		claimSessionID := "claim-session-should-be-ignored"

		tokenResult, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			WithSessionID(expectedSessionID).
			WithClaim("session_id", claimSessionID).
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token: %v", err)
		}

		// Validate the token to extract claims
		claims, err := tm.ValidateJWTWithHMAC(tokenResult.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token: %v", err)
		}

		// Check that WithSessionID took precedence
		if claims.SessionID != expectedSessionID {
			t.Errorf("Expected WithSessionID to take precedence: expected %s, got %s", expectedSessionID, claims.SessionID)
		}

		t.Logf("WithSessionID took precedence: %s", claims.SessionID)
	})

	// Test 6: Test that different tokens get different session_ids when not specified
	t.Run("Different session_ids for different tokens", func(t *testing.T) {
		token1, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token 1: %v", err)
		}

		token2, err := tm.NewToken().
			WithIssuer("test-issuer").
			WithSubject("test-subject").
			WithAudience("test-audience").
			CreateJWTWithHMAC(SigningMethodHS256)

		if err != nil {
			t.Fatalf("Failed to create token 2: %v", err)
		}

		// Validate both tokens
		claims1, err := tm.ValidateJWTWithHMAC(token1.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token 1: %v", err)
		}

		claims2, err := tm.ValidateJWTWithHMAC(token2.Token, SigningMethodHS256)
		if err != nil {
			t.Fatalf("Failed to validate token 2: %v", err)
		}

		// Check that session_ids are different
		if claims1.SessionID == claims2.SessionID {
			t.Error("Expected different session_ids for different tokens, but they were the same")
		}

		t.Logf("Token 1 session_id: %s", claims1.SessionID)
		t.Logf("Token 2 session_id: %s", claims2.SessionID)
	})
}
