package tokeno

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"
)

func TestEncryptedOpaqueToken(t *testing.T) {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Create TokenManager with encryption enabled
	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("test-secret")).
		WithOpaqueEncryption(encryptionKey, true).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token request
	req := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"user_id": "12345",
			"role":    "admin",
		},
	}

	// Create opaque token
	result, err := tm.CreateOpaqueToken(req)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify token is base64 encoded but not JSON decodable (should be encrypted)
	decodedBytes, err := base64.URLEncoding.DecodeString(result.Token)
	if err != nil {
		t.Error("Token should be base64 encoded for transmission")
	}

	// Try to unmarshal as JSON - this should fail for encrypted tokens
	var testData map[string]interface{}
	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Error("Token should not be JSON decodable when encrypted")
	}

	// Validate the token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	// Verify the claims
	if validatedReq.Issuer != req.Issuer {
		t.Errorf("Expected issuer %s, got %s", req.Issuer, validatedReq.Issuer)
	}
	if validatedReq.Subject != req.Subject {
		t.Errorf("Expected subject %s, got %s", req.Subject, validatedReq.Subject)
	}
	if validatedReq.Audience != req.Audience {
		t.Errorf("Expected audience %s, got %s", req.Audience, validatedReq.Audience)
	}
	if validatedReq.CustomClaims["user_id"] != "12345" {
		t.Errorf("Expected user_id 12345, got %v", validatedReq.CustomClaims["user_id"])
	}
	if validatedReq.CustomClaims["role"] != "admin" {
		t.Errorf("Expected role admin, got %v", validatedReq.CustomClaims["role"])
	}

	t.Logf("Encrypted opaque token created successfully: %s", result.Token[:50]+"...")
}

func TestEncryptedOpaqueTokenWithHMAC(t *testing.T) {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Create TokenManager with encryption enabled
	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("test-secret")).
		WithOpaqueEncryption(encryptionKey, true).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token request
	req := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"user_id": "67890",
			"role":    "user",
		},
	}

	// Create opaque token using TokenBuilder
	tokenBuilder := tm.NewToken().
		WithIssuer(req.Issuer).
		WithSubject(req.Subject).
		WithAudience(req.Audience).
		WithExpiration(req.ExpiresAt).
		WithIssuedAt(req.IssuedAt).
		WithClaim("user_id", "67890").
		WithClaim("role", "user")

	result, err := tokenBuilder.CreateOpaqueWithHMAC(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify token is base64 encoded but not JSON decodable (should be encrypted)
	decodedBytes, err := base64.URLEncoding.DecodeString(result.Token)
	if err != nil {
		t.Error("Token should be base64 encoded for transmission")
	}

	// Try to unmarshal as JSON - this should fail for encrypted tokens
	var testData map[string]interface{}
	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Error("Token should not be JSON decodable when encrypted")
	}

	// Validate the token
	validatedReq, err := tm.ValidateOpaqueWithHMAC(result.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	// Verify the claims
	if validatedReq.Issuer != req.Issuer {
		t.Errorf("Expected issuer %s, got %s", req.Issuer, validatedReq.Issuer)
	}
	if validatedReq.Subject != req.Subject {
		t.Errorf("Expected subject %s, got %s", req.Subject, validatedReq.Subject)
	}
	if validatedReq.Audience != req.Audience {
		t.Errorf("Expected audience %s, got %s", req.Audience, validatedReq.Audience)
	}
	if validatedReq.CustomClaims["user_id"] != "67890" {
		t.Errorf("Expected user_id 67890, got %v", validatedReq.CustomClaims["user_id"])
	}
	if validatedReq.CustomClaims["role"] != "user" {
		t.Errorf("Expected role user, got %v", validatedReq.CustomClaims["role"])
	}

	t.Logf("Encrypted opaque token with HMAC created successfully: %s", result.Token[:50]+"...")
}

func TestEncryptedOpaqueTokenWithKeyPair(t *testing.T) {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Generate RSA key pair
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create TokenManager with encryption enabled
	tm := NewTokenManagerBuilder().
		WithOpaqueEncryption(encryptionKey, true).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token request
	req := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"user_id": "11111",
			"role":    "superadmin",
		},
	}

	// Create opaque token using TokenBuilder with key pair
	tokenBuilder := tm.NewToken().
		WithIssuer(req.Issuer).
		WithSubject(req.Subject).
		WithAudience(req.Audience).
		WithExpiration(req.ExpiresAt).
		WithIssuedAt(req.IssuedAt).
		WithClaim("user_id", "11111").
		WithClaim("role", "superadmin")

	result, err := tokenBuilder.CreateOpaqueWithKeyPair(*keyPair)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify token is base64 encoded but not JSON decodable (should be encrypted)
	decodedBytes, err := base64.URLEncoding.DecodeString(result.Token)
	if err != nil {
		t.Error("Token should be base64 encoded for transmission")
	}

	// Try to unmarshal as JSON - this should fail for encrypted tokens
	var testData map[string]interface{}
	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Error("Token should not be JSON decodable when encrypted")
	}

	// Validate the token
	validatedReq, err := tm.ValidateOpaqueWithKeyPair(result.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	// Verify the claims
	if validatedReq.Issuer != req.Issuer {
		t.Errorf("Expected issuer %s, got %s", req.Issuer, validatedReq.Issuer)
	}
	if validatedReq.Subject != req.Subject {
		t.Errorf("Expected subject %s, got %s", req.Subject, validatedReq.Subject)
	}
	if validatedReq.Audience != req.Audience {
		t.Errorf("Expected audience %s, got %s", req.Audience, validatedReq.Audience)
	}
	if validatedReq.CustomClaims["user_id"] != "11111" {
		t.Errorf("Expected user_id 11111, got %v", validatedReq.CustomClaims["user_id"])
	}
	if validatedReq.CustomClaims["role"] != "superadmin" {
		t.Errorf("Expected role superadmin, got %v", validatedReq.CustomClaims["role"])
	}

	t.Logf("Encrypted opaque token with key pair created successfully: %s", result.Token[:50]+"...")
}

func TestEncryptedOpaqueTokenSecurity(t *testing.T) {
	// Generate a random 32-byte encryption key
	encryptionKey := make([]byte, 32)
	if _, err := rand.Read(encryptionKey); err != nil {
		t.Fatalf("Failed to generate encryption key: %v", err)
	}

	// Create TokenManager with encryption enabled
	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("test-secret")).
		WithOpaqueEncryption(encryptionKey, true).
		WithDefaultExpiration(1 * time.Hour).
		Build()

	// Create a token request with sensitive data
	req := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: time.Now().Add(1 * time.Hour),
		IssuedAt:  time.Now(),
		CustomClaims: map[string]interface{}{
			"user_id":     "12345",
			"role":        "admin",
			"permissions": []string{"read", "write", "delete"},
			"secret_key":  "super-secret-key-123",
		},
	}

	// Create opaque token
	result, err := tm.CreateOpaqueToken(req)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Verify that the token does not contain any readable data
	tokenStr := result.Token
	if len(tokenStr) > 0 && (tokenStr == "test-issuer" || len(tokenStr) > len("test-issuer") && (tokenStr[:len("test-issuer")] == "test-issuer" || tokenStr[len(tokenStr)-len("test-issuer"):] == "test-issuer")) {
		t.Error("Token should not contain readable issuer")
	}
	if len(tokenStr) > 0 && (tokenStr == "test-subject" || len(tokenStr) > len("test-subject") && (tokenStr[:len("test-subject")] == "test-subject" || tokenStr[len(tokenStr)-len("test-subject"):] == "test-subject")) {
		t.Error("Token should not contain readable subject")
	}
	if len(tokenStr) > 0 && (tokenStr == "admin" || len(tokenStr) > len("admin") && (tokenStr[:len("admin")] == "admin" || tokenStr[len(tokenStr)-len("admin"):] == "admin")) {
		t.Error("Token should not contain readable role")
	}
	if len(tokenStr) > 0 && (tokenStr == "super-secret-key-123" || len(tokenStr) > len("super-secret-key-123") && (tokenStr[:len("super-secret-key-123")] == "super-secret-key-123" || tokenStr[len(tokenStr)-len("super-secret-key-123"):] == "super-secret-key-123")) {
		t.Error("Token should not contain readable secret key")
	}

	// Verify that the token is properly encrypted (base64 encoded but not JSON decodable)
	decodedBytes, err := base64.URLEncoding.DecodeString(tokenStr)
	if err != nil {
		t.Error("Token should be base64 encoded for transmission")
	}

	// Try to unmarshal as JSON - this should fail for encrypted tokens
	var testData map[string]interface{}
	if json.Unmarshal(decodedBytes, &testData) == nil {
		t.Error("Token should not be JSON decodable when encrypted")
	}

	// Validate the token to ensure it still works
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	// Verify all claims are preserved
	if validatedReq.CustomClaims["secret_key"] != "super-secret-key-123" {
		t.Errorf("Expected secret_key to be preserved, got %v", validatedReq.CustomClaims["secret_key"])
	}

	t.Logf("Encrypted opaque token security test passed: %s", result.Token[:50]+"...")
}
