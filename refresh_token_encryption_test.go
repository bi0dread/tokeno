package tokeno

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestRefreshTokenEncryption(t *testing.T) {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Create TokenManager with encryption enabled and refresh config
	refreshConfig := &TokenRefreshConfig{
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		MaxRefreshAttempts: 5,
	}

	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("test-secret")).
		WithOpaqueEncryption(encryptionKey, true).
		WithRefreshConfig(refreshConfig).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create opaque token with refresh token using TokenBuilder
	tokenBuilder := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithIssuedAt(time.Now()).
		WithClaim("user_id", "12345").
		WithClaim("role", "admin")

	result, err := tokenBuilder.CreateOpaqueWithHMAC(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify that both access token and refresh token are encrypted
	t.Run("Access Token Encryption", func(t *testing.T) {
		// Verify access token is encrypted
		decodedBytes, err := base64.URLEncoding.DecodeString(result.Token)
		if err != nil {
			t.Error("Access token should be base64 encoded for transmission")
		}

		var testData map[string]interface{}
		if json.Unmarshal(decodedBytes, &testData) == nil {
			t.Error("Access token should not be JSON decodable when encrypted")
		}
	})

	t.Run("Refresh Token Encryption", func(t *testing.T) {
		if result.RefreshToken == "" {
			t.Fatal("Refresh token should be generated")
		}

		// Verify refresh token is encrypted
		decodedBytes, err := base64.URLEncoding.DecodeString(result.RefreshToken)
		if err != nil {
			t.Error("Refresh token should be base64 encoded for transmission")
		}

		var testData map[string]interface{}
		if json.Unmarshal(decodedBytes, &testData) == nil {
			t.Error("Refresh token should not be JSON decodable when encrypted")
		}
	})

	t.Run("Refresh Token Security", func(t *testing.T) {
		// Verify that refresh token does not contain readable data
		refreshTokenStr := result.RefreshToken
		sensitiveData := []string{"test-issuer", "test-subject", "admin", "12345"}

		for _, data := range sensitiveData {
			if len(refreshTokenStr) > 0 && (refreshTokenStr == data || len(refreshTokenStr) > len(data) && (refreshTokenStr[:len(data)] == data || refreshTokenStr[len(refreshTokenStr)-len(data):] == data)) {
				t.Errorf("❌ SECURITY ISSUE: Refresh token contains readable data: %s", data)
			}
		}
	})

	t.Run("Token Refresh Flow", func(t *testing.T) {
		// Test the refresh flow
		newResult, err := tm.RefreshToken(result.RefreshToken)
		if err != nil {
			t.Fatalf("Failed to refresh token: %v", err)
		}

		// Verify new access token is also encrypted
		decodedBytes, err := base64.URLEncoding.DecodeString(newResult.Token)
		if err != nil {
			t.Error("New access token should be base64 encoded for transmission")
		}

		var testData map[string]interface{}
		if json.Unmarshal(decodedBytes, &testData) == nil {
			t.Error("New access token should not be JSON decodable when encrypted")
		}

		// Verify new refresh token is also encrypted
		if newResult.RefreshToken == "" {
			t.Fatal("New refresh token should be generated")
		}

		decodedBytes, err = base64.URLEncoding.DecodeString(newResult.RefreshToken)
		if err != nil {
			t.Error("New refresh token should be base64 encoded for transmission")
		}

		if json.Unmarshal(decodedBytes, &testData) == nil {
			t.Error("New refresh token should not be JSON decodable when encrypted")
		}

		// Validate the new access token
		validatedReq, err := tm.ValidateOpaqueToken(newResult.Token)
		if err != nil {
			t.Fatalf("Failed to validate refreshed token: %v", err)
		}

		// Verify claims are preserved
		if validatedReq.Issuer != "test-issuer" {
			t.Errorf("Expected issuer test-issuer, got %s", validatedReq.Issuer)
		}
		if validatedReq.Subject != "test-subject" {
			t.Errorf("Expected subject test-subject, got %s", validatedReq.Subject)
		}
		if validatedReq.CustomClaims["user_id"] != "12345" {
			t.Errorf("Expected user_id 12345, got %v", validatedReq.CustomClaims["user_id"])
		}
		if validatedReq.CustomClaims["role"] != "admin" {
			t.Errorf("Expected role admin, got %v", validatedReq.CustomClaims["role"])
		}

		// Verify refreshed claim is added
		if validatedReq.CustomClaims["refreshed"] != true {
			t.Error("Expected refreshed claim to be true")
		}
	})

	if len(result.Token) > 50 {
		t.Logf("Access Token: %s", result.Token[:50]+"...")
	} else {
		t.Logf("Access Token: %s", result.Token)
	}
	if len(result.RefreshToken) > 50 {
		t.Logf("Refresh Token: %s", result.RefreshToken[:50]+"...")
	} else {
		t.Logf("Refresh Token: %s", result.RefreshToken)
	}
}

func TestRefreshTokenWithoutEncryption(t *testing.T) {
	// Test refresh tokens without encryption for comparison
	refreshConfig := &TokenRefreshConfig{
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		MaxRefreshAttempts: 5,
	}

	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("test-secret")).
		WithOpaqueEncryption([]byte("dummy-key"), false). // Disable encryption
		WithRefreshConfig(refreshConfig).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create opaque token with refresh token using TokenBuilder
	tokenBuilder := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpiration(time.Now().Add(1*time.Hour)).
		WithIssuedAt(time.Now()).
		WithClaim("user_id", "12345").
		WithClaim("role", "admin")

	result, err := tokenBuilder.CreateOpaqueWithHMAC(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify that refresh token is JSON decodable (not encrypted)
	decodedBytes, err := base64.URLEncoding.DecodeString(result.RefreshToken)
	if err != nil {
		t.Error("Refresh token should be base64 encoded for transmission")
	}

	var testData map[string]interface{}
	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Log("✅ Non-encrypted refresh token is JSON decodable (data is visible)")
		t.Logf("Decoded refresh token data: %+v", testData)
	} else {
		t.Error("Non-encrypted refresh token should be JSON decodable")
	}

	// Test refresh flow
	newResult, err := tm.RefreshToken(result.RefreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	// Verify new refresh token is also JSON decodable
	decodedBytes, err = base64.URLEncoding.DecodeString(newResult.RefreshToken)
	if err != nil {
		t.Error("New refresh token should be base64 encoded for transmission")
	}

	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Log("✅ New non-encrypted refresh token is JSON decodable (data is visible)")
		t.Logf("Decoded new refresh token data: %+v", testData)
	} else {
		t.Error("New non-encrypted refresh token should be JSON decodable")
	}
}
