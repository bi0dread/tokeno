package tokeno

import (
	"crypto/elliptic"
	"fmt"
	"testing"
	"time"
)

func TestNewTokenManager(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-secret"),
		OpaqueSecretKey:   []byte("opaque-secret"),
		OpaqueTokenLength: 16,
		DefaultExpiration: 2 * time.Hour,
	}

	tm := NewTokenManager(config)

	if tm == nil {
		t.Fatal("TokenManager should not be nil")
	}

	if tm.config.JWTSecretKey == nil {
		t.Error("JWTSecretKey should be set")
	}

	if tm.config.OpaqueSecretKey == nil {
		t.Error("OpaqueSecretKey should be set")
	}

	if tm.config.OpaqueTokenLength != 16 {
		t.Errorf("Expected OpaqueTokenLength 16, got %d", tm.config.OpaqueTokenLength)
	}

	if tm.config.DefaultExpiration != 2*time.Hour {
		t.Errorf("Expected DefaultExpiration 2h, got %v", tm.config.DefaultExpiration)
	}
}

func TestNewTokenManagerWithDefaults(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	if tm.config.OpaqueTokenLength == 0 {
		t.Error("OpaqueTokenLength should have default value")
	}

	if tm.config.DefaultExpiration == 0 {
		t.Error("DefaultExpiration should have default value")
	}

	if tm.config.JWTMethod == "" {
		t.Error("JWTMethod should have default value")
	}
}

func TestTokenManagerCreateJWTToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	result, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Type != TokenTypeJWT {
		t.Errorf("Expected token type JWT, got %s", result.Type)
	}

	if result.Token == "" {
		t.Error("Token should not be empty")
	}

	if result.ExpiresAt != tokenReq.ExpiresAt {
		t.Error("ExpiresAt should match token request")
	}

	if result.IssuedAt != tokenReq.IssuedAt {
		t.Error("IssuedAt should match token request")
	}
}

func TestTokenManagerCreateOpaqueToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	if result == nil {
		t.Fatal("Result should not be nil")
	}

	if result.Type != TokenTypeOpaque {
		t.Errorf("Expected token type Opaque, got %s", result.Type)
	}

	if result.Token == "" {
		t.Error("Token should not be empty")
	}

	if result.ExpiresAt != tokenReq.ExpiresAt {
		t.Error("ExpiresAt should match token request")
	}

	if result.IssuedAt != tokenReq.IssuedAt {
		t.Error("IssuedAt should match token request")
	}
}

func TestTokenManagerValidateJWTToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	// Create JWT token
	result, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Validate JWT token
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate JWT token: %v", err)
	}

	if validatedReq == nil {
		t.Fatal("Validated request should not be nil")
	}

	// Check basic claims
	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}

	if validatedReq.Subject != tokenReq.Subject {
		t.Errorf("Expected subject %s, got %s", tokenReq.Subject, validatedReq.Subject)
	}

	if validatedReq.Audience != tokenReq.Audience {
		t.Errorf("Expected audience %s, got %s", tokenReq.Audience, validatedReq.Audience)
	}

	// Check custom claims
	if validatedReq.CustomClaims["role"] != tokenReq.CustomClaims["role"] {
		t.Errorf("Expected role %v, got %v", tokenReq.CustomClaims["role"], validatedReq.CustomClaims["role"])
	}
}

func TestTokenManagerValidateOpaqueToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	// Create opaque token
	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Validate opaque token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	if validatedReq == nil {
		t.Fatal("Validated request should not be nil")
	}

	// Check basic claims
	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}

	if validatedReq.Subject != tokenReq.Subject {
		t.Errorf("Expected subject %s, got %s", tokenReq.Subject, validatedReq.Subject)
	}

	if validatedReq.Audience != tokenReq.Audience {
		t.Errorf("Expected audience %s, got %s", tokenReq.Audience, validatedReq.Audience)
	}

	// Check custom claims
	if validatedReq.CustomClaims["role"] != tokenReq.CustomClaims["role"] {
		t.Errorf("Expected role %v, got %v", tokenReq.CustomClaims["role"], validatedReq.CustomClaims["role"])
	}
}

func TestTokenManagerValidateToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	// Test JWT token validation
	jwtResult, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	validatedReq, err := tm.ValidateToken(jwtResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate JWT token: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("JWT validation failed: expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}

	// Test opaque token validation
	opaqueResult, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	validatedReq, err = tm.ValidateToken(opaqueResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Opaque validation failed: expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}
}

func TestTokenManagerDetectTokenType(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	// Test JWT token detection
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	tokenType := tm.detectTokenType(jwtToken)
	if tokenType != TokenTypeJWT {
		t.Errorf("Expected JWT token type, got %s", tokenType)
	}

	// Test opaque token detection
	opaqueToken := "dGVzdC1vcGFxdWUtdG9rZW4="
	tokenType = tm.detectTokenType(opaqueToken)
	if tokenType != TokenTypeOpaque {
		t.Errorf("Expected Opaque token type, got %s", tokenType)
	}
}

func TestTokenManagerWithJWTKeyPair(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
		JWTKeyPair:      keyPair,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	// Create JWT token with key pair
	result, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create JWT token with key pair: %v", err)
	}

	// Validate JWT token
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate JWT token with key pair: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}
}

func TestTokenManagerWithOpaqueKeyPair(t *testing.T) {
	// Generate RSA key pair for opaque tokens
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
		OpaqueKeyPair:   keyPair,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "user",
		},
	}

	// Create opaque token with key pair
	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token with key pair: %v", err)
	}

	// Validate opaque token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with key pair: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}

	if validatedReq.CustomClaims["role"] != tokenReq.CustomClaims["role"] {
		t.Errorf("Expected role %v, got %v", tokenReq.CustomClaims["role"], validatedReq.CustomClaims["role"])
	}
}

func TestTokenManagerWithECDSAOpaqueKeyPair(t *testing.T) {
	// Generate ECDSA key pair for opaque tokens
	keyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
		OpaqueKeyPair:   keyPair,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	// Create opaque token with ECDSA key pair
	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token with ECDSA key pair: %v", err)
	}

	// Validate opaque token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with ECDSA key pair: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}
}

func TestTokenManagerWithEdDSAOpaqueKeyPair(t *testing.T) {
	// Generate EdDSA key pair for opaque tokens
	keyPair, err := GenerateEdDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate EdDSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
		OpaqueKeyPair:   keyPair,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	// Create opaque token with EdDSA key pair
	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token with EdDSA key pair: %v", err)
	}

	// Validate opaque token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with EdDSA key pair: %v", err)
	}

	if validatedReq.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedReq.Issuer)
	}
}

func TestTokenManagerExplicitHMACFunctions(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-jwt-secret"),
		OpaqueSecretKey:   []byte("test-opaque-secret"),
		OpaqueTokenLength: 32,
		DefaultExpiration: time.Hour,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "admin",
		},
	}

	// Test JWT HMAC creation and validation using TokenBuilder
	jwtResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token with HMAC: %v", err)
	}

	validatedJWT, err := tm.ValidateJWTWithHMAC(jwtResult.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate JWT token with HMAC: %v", err)
	}

	if validatedJWT.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedJWT.Issuer)
	}

	// Test Opaque HMAC creation and validation using TokenBuilder
	opaqueResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateOpaqueWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create opaque token with HMAC: %v", err)
	}

	validatedOpaque, err := tm.ValidateOpaqueWithHMAC(opaqueResult.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with HMAC: %v", err)
	}

	if validatedOpaque.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedOpaque.Issuer)
	}
}

func TestTokenManagerExplicitKeyPairFunctions(t *testing.T) {
	// Generate RSA key pair
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-jwt-secret"),
		OpaqueSecretKey:   []byte("test-opaque-secret"),
		OpaqueTokenLength: 32,
		DefaultExpiration: time.Hour,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role": "admin",
		},
	}

	// Test JWT with key pair creation and validation using TokenBuilder
	jwtResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateJWTWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create JWT token with key pair: %v", err)
	}

	validatedJWT, err := tm.ValidateJWTWithKeyPair(jwtResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate JWT token with key pair: %v", err)
	}

	if validatedJWT.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedJWT.Issuer)
	}

	// Test Opaque with key pair creation and validation using TokenBuilder
	opaqueResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateOpaqueWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create opaque token with key pair: %v", err)
	}

	validatedOpaque, err := tm.ValidateOpaqueWithKeyPair(opaqueResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with key pair: %v", err)
	}

	if validatedOpaque.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedOpaque.Issuer)
	}
}

func TestTokenManagerExplicitECDSAFunctions(t *testing.T) {
	// Generate ECDSA key pair
	keyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-jwt-secret"),
		OpaqueSecretKey:   []byte("test-opaque-secret"),
		OpaqueTokenLength: 32,
		DefaultExpiration: time.Hour,
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	// Test JWT with ECDSA key pair using TokenBuilder
	jwtResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		CreateJWTWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create JWT token with ECDSA key pair: %v", err)
	}

	validatedJWT, err := tm.ValidateJWTWithKeyPair(jwtResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate JWT token with ECDSA key pair: %v", err)
	}

	if validatedJWT.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedJWT.Issuer)
	}

	// Test Opaque with ECDSA key pair using TokenBuilder
	opaqueResult, err := tm.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		CreateOpaqueWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create opaque token with ECDSA key pair: %v", err)
	}

	validatedOpaque, err := tm.ValidateOpaqueWithKeyPair(opaqueResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with ECDSA key pair: %v", err)
	}

	if validatedOpaque.Issuer != tokenReq.Issuer {
		t.Errorf("Expected issuer %s, got %s", tokenReq.Issuer, validatedOpaque.Issuer)
	}
}

func TestTokenManagerExpiredToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(-time.Hour), // Expired token
		NotBefore: now.Add(-2 * time.Hour),
		IssuedAt:  now.Add(-2 * time.Hour),
	}

	// Test expired opaque token
	result, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Wait a bit to ensure token is expired
	time.Sleep(10 * time.Millisecond)

	_, err = tm.ValidateOpaqueToken(result.Token)
	if err == nil {
		t.Error("Expected error for expired opaque token")
	}

	if err != nil && err.Error() != "opaque token has expired" {
		t.Errorf("Expected 'opaque token has expired' error, got: %v", err)
	}
}

func TestTokenManagerInvalidToken(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:    []byte("test-secret"),
		OpaqueSecretKey: []byte("opaque-secret"),
	}

	tm := NewTokenManager(config)

	// Test invalid JWT token
	_, err := tm.ValidateJWTToken("invalid.jwt.token")
	if err == nil {
		t.Error("Expected error for invalid JWT token")
	}

	// Test invalid opaque token
	_, err = tm.ValidateOpaqueToken("invalid-opaque-token")
	if err == nil {
		t.Error("Expected error for invalid opaque token")
	}

	// Test invalid base64 opaque token
	_, err = tm.ValidateOpaqueToken("invalid-base64!")
	if err == nil {
		t.Error("Expected error for invalid base64 opaque token")
	}
}

func TestTokenManagerDefaultExpiration(t *testing.T) {
	config := &TokenManagerConfig{
		JWTSecretKey:      []byte("test-secret"),
		OpaqueSecretKey:   []byte("opaque-secret"),
		DefaultExpiration: 1 * time.Hour,
	}

	tm := NewTokenManager(config)

	// Create token request without expiration
	tokenReq := TokenRequest{
		Issuer:   "test-issuer",
		Subject:  "test-subject",
		Audience: "test-audience",
		// ExpiresAt not set - should use default
	}

	// Test JWT token with default expiration
	jwtResult, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create JWT token: %v", err)
	}

	// Check that expiration was set
	expectedExpiration := time.Now().Add(1 * time.Hour)
	if jwtResult.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) ||
		jwtResult.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected expiration around %v, got %v", expectedExpiration, jwtResult.ExpiresAt)
	}

	// Test opaque token with default expiration
	opaqueResult, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		t.Fatalf("Failed to create opaque token: %v", err)
	}

	// Check that expiration was set
	if opaqueResult.ExpiresAt.Before(expectedExpiration.Add(-time.Minute)) ||
		opaqueResult.ExpiresAt.After(expectedExpiration.Add(time.Minute)) {
		t.Errorf("Expected expiration around %v, got %v", expectedExpiration, opaqueResult.ExpiresAt)
	}
}

func TestTokenManagerBuilder(t *testing.T) {
	// Test basic builder functionality
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		WithJWTMethod(SigningMethodHS256).
		WithDefaultExpiration(2 * time.Hour).
		WithOpaqueTokenLength(64).
		Build()

	if tm == nil {
		t.Fatal("Expected TokenManager, got nil")
	}

	// Test that configuration was set correctly
	if string(tm.config.JWTSecretKey) != "jwt-secret" {
		t.Errorf("Expected JWT secret 'jwt-secret', got '%s'", string(tm.config.JWTSecretKey))
	}

	if string(tm.config.OpaqueSecretKey) != "opaque-secret" {
		t.Errorf("Expected opaque secret 'opaque-secret', got '%s'", string(tm.config.OpaqueSecretKey))
	}

	if tm.config.JWTMethod != SigningMethodHS256 {
		t.Errorf("Expected JWT method %s, got %s", SigningMethodHS256, tm.config.JWTMethod)
	}

	if tm.config.DefaultExpiration != 2*time.Hour {
		t.Errorf("Expected default expiration 2h, got %v", tm.config.DefaultExpiration)
	}

	if tm.config.OpaqueTokenLength != 64 {
		t.Errorf("Expected opaque token length 64, got %d", tm.config.OpaqueTokenLength)
	}
}

func TestTokenManagerBuilderWithKeyPairs(t *testing.T) {
	// Generate test key pairs
	rsaKeyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	// Test builder with key pairs
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		WithJWTKeyPair(rsaKeyPair).
		WithOpaqueKeyPair(ecdsaKeyPair).
		Build()

	if tm.config.JWTKeyPair == nil {
		t.Error("Expected JWT key pair to be set")
	}

	if tm.config.OpaqueKeyPair == nil {
		t.Error("Expected opaque key pair to be set")
	}

	if tm.config.JWTKeyPair.Method != rsaKeyPair.Method {
		t.Errorf("Expected JWT key pair method %s, got %s", rsaKeyPair.Method, tm.config.JWTKeyPair.Method)
	}

	if tm.config.OpaqueKeyPair.Method != ecdsaKeyPair.Method {
		t.Errorf("Expected opaque key pair method %s, got %s", ecdsaKeyPair.Method, tm.config.OpaqueKeyPair.Method)
	}
}

func TestTokenBuilder(t *testing.T) {
	// Create TokenManager using builder
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	now := time.Now()

	// Test token builder with method chaining
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpirationDuration(2*time.Hour).
		WithNotBefore(now).
		WithIssuedAt(now).
		WithClaim("role", "admin").
		WithClaim("permissions", []string{"read", "write"}).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token with builder: %v", err)
	}

	// Validate the token
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate JWT token: %v", err)
	}

	// Check token claims
	if validatedReq.Issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got '%s'", validatedReq.Issuer)
	}

	if validatedReq.Subject != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got '%s'", validatedReq.Subject)
	}

	if validatedReq.Audience != "test-audience" {
		t.Errorf("Expected audience 'test-audience', got '%s'", validatedReq.Audience)
	}

	if validatedReq.CustomClaims["role"] != "admin" {
		t.Errorf("Expected role 'admin', got '%v'", validatedReq.CustomClaims["role"])
	}

	permissions, ok := validatedReq.CustomClaims["permissions"].([]interface{})
	if !ok {
		t.Fatalf("Expected permissions to be []interface{}, got %T", validatedReq.CustomClaims["permissions"])
	}

	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}
}

func TestTokenBuilderWithClaims(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	claims := map[string]interface{}{
		"role":        "user",
		"permissions": []string{"read"},
		"user_id":     123,
		"active":      true,
	}

	// Test WithClaims method
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaims(claims).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create JWT token with claims: %v", err)
	}

	// Validate the token
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate JWT token: %v", err)
	}

	// Check all claims
	for key, expectedValue := range claims {
		actualValue := validatedReq.CustomClaims[key]

		// Handle slice comparison specially
		if key == "permissions" {
			expectedPerms := expectedValue.([]string)
			actualPerms, ok := actualValue.([]interface{})
			if !ok {
				t.Errorf("Expected permissions to be []interface{}, got %T", actualValue)
				continue
			}

			if len(actualPerms) != len(expectedPerms) {
				t.Errorf("Expected %d permissions, got %d", len(expectedPerms), len(actualPerms))
				continue
			}

			for i, expectedPerm := range expectedPerms {
				if actualPerms[i] != expectedPerm {
					t.Errorf("Expected permission[%d] to be %s, got %v", i, expectedPerm, actualPerms[i])
				}
			}
		} else if key == "user_id" {
			// Handle number conversion
			expectedNum := expectedValue.(int)
			actualNum, ok := actualValue.(float64)
			if !ok {
				t.Errorf("Expected user_id to be float64, got %T", actualValue)
				continue
			}
			if int(actualNum) != expectedNum {
				t.Errorf("Expected user_id to be %d, got %d", expectedNum, int(actualNum))
			}
		} else {
			if actualValue != expectedValue {
				t.Errorf("Expected claim %s to be %v, got %v", key, expectedValue, actualValue)
			}
		}
	}
}

func TestTokenBuilderWithOpaqueTokens(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test opaque token creation with builder
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpirationDuration(time.Hour).
		WithClaim("role", "admin").
		CreateOpaqueWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create opaque token with builder: %v", err)
	}

	// Validate the token
	validatedReq, err := tm.ValidateOpaqueToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	if validatedReq.Issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got '%s'", validatedReq.Issuer)
	}

	if validatedReq.CustomClaims["role"] != "admin" {
		t.Errorf("Expected role 'admin', got '%v'", validatedReq.CustomClaims["role"])
	}
}

func TestTokenBuilderWithKeyPairs(t *testing.T) {
	// Generate test key pair
	keyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test JWT with key pair
	jwtResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("role", "admin").
		CreateJWTWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create JWT with key pair: %v", err)
	}

	// Validate JWT with key pair using TokenBuilder
	_, err = tm.ValidateJWTWithKeyPair(jwtResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate JWT with key pair: %v", err)
	}

	// Test opaque token with key pair
	opaqueResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("role", "admin").
		CreateOpaqueWithKeyPair(*keyPair)

	if err != nil {
		t.Fatalf("Failed to create opaque token with key pair: %v", err)
	}

	// Validate opaque token with key pair using TokenBuilder
	_, err = tm.ValidateOpaqueWithKeyPair(opaqueResult.Token, *keyPair)
	if err != nil {
		t.Fatalf("Failed to validate opaque token with key pair: %v", err)
	}
}

func TestTokenBuilderEdgeCases(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test empty token builder
	emptyResult, err := tm.NewToken().CreateJWTWithHMAC(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create empty token: %v", err)
	}

	// Validate empty token
	validatedReq, err := tm.ValidateJWTToken(emptyResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate empty token: %v", err)
	}

	// Check that empty values are handled correctly
	if validatedReq.Issuer != "" {
		t.Errorf("Expected empty issuer, got '%s'", validatedReq.Issuer)
	}

	if validatedReq.Subject != "" {
		t.Errorf("Expected empty subject, got '%s'", validatedReq.Subject)
	}

	// Test token with only custom claims
	claimsResult, err := tm.NewToken().
		WithClaim("role", "admin").
		WithClaim("permissions", []string{"read", "write"}).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create token with only claims: %v", err)
	}

	// Validate token with only claims
	validatedClaims, err := tm.ValidateJWTToken(claimsResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate token with claims: %v", err)
	}

	if validatedClaims.CustomClaims["role"] != "admin" {
		t.Errorf("Expected role 'admin', got '%v'", validatedClaims.CustomClaims["role"])
	}
}

func TestTokenBuilderTimeHandling(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	now := time.Now()

	// Test with absolute time
	absoluteResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithExpiration(now.Add(2 * time.Hour)).
		WithNotBefore(now).
		WithIssuedAt(now).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create token with absolute time: %v", err)
	}

	// Validate absolute time token
	validatedAbsolute, err := tm.ValidateJWTToken(absoluteResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate absolute time token: %v", err)
	}

	// Check that times are set correctly
	if validatedAbsolute.ExpiresAt.Sub(now.Add(2*time.Hour)) > time.Second {
		t.Errorf("Expected expiration around %v, got %v", now.Add(2*time.Hour), validatedAbsolute.ExpiresAt)
	}

	// Test with duration
	durationResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithExpirationDuration(3 * time.Hour).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create token with duration: %v", err)
	}

	// Validate duration token
	validatedDuration, err := tm.ValidateJWTToken(durationResult.Token)
	if err != nil {
		t.Fatalf("Failed to validate duration token: %v", err)
	}

	// Check that duration was applied correctly
	expectedExpiration := now.Add(3 * time.Hour)
	if validatedDuration.ExpiresAt.Sub(expectedExpiration) > time.Second {
		t.Errorf("Expected expiration around %v, got %v", expectedExpiration, validatedDuration.ExpiresAt)
	}
}

func TestTokenBuilderComplexClaims(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test complex nested claims
	complexClaims := map[string]interface{}{
		"user": map[string]interface{}{
			"id":     123,
			"name":   "John Doe",
			"email":  "john@example.com",
			"active": true,
			"roles":  []string{"admin", "user"},
			"metadata": map[string]interface{}{
				"department": "engineering",
				"level":      "senior",
			},
		},
		"permissions": []string{"read", "write", "delete"},
		"features": map[string]bool{
			"analytics": true,
			"reporting": false,
		},
		"settings": map[string]interface{}{
			"theme":    "dark",
			"language": "en",
			"notifications": map[string]bool{
				"email": true,
				"sms":   false,
			},
		},
	}

	// Create token with complex claims
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaims(complexClaims).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create token with complex claims: %v", err)
	}

	// Validate token with complex claims
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate token with complex claims: %v", err)
	}

	// Check nested user claims
	userClaims, ok := validatedReq.CustomClaims["user"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected user claims to be map[string]interface{}, got %T", validatedReq.CustomClaims["user"])
	}

	if userClaims["id"] != float64(123) {
		t.Errorf("Expected user id 123, got %v", userClaims["id"])
	}

	if userClaims["name"] != "John Doe" {
		t.Errorf("Expected user name 'John Doe', got '%v'", userClaims["name"])
	}

	// Check permissions
	permissions, ok := validatedReq.CustomClaims["permissions"].([]interface{})
	if !ok {
		t.Fatalf("Expected permissions to be []interface{}, got %T", validatedReq.CustomClaims["permissions"])
	}

	if len(permissions) != 3 {
		t.Errorf("Expected 3 permissions, got %d", len(permissions))
	}

	// Check features
	features, ok := validatedReq.CustomClaims["features"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected features to be map[string]interface{}, got %T", validatedReq.CustomClaims["features"])
	}

	if features["analytics"] != true {
		t.Errorf("Expected analytics to be true, got %v", features["analytics"])
	}
}

func TestTokenBuilderAllSigningMethods(t *testing.T) {
	// Generate key pairs for different methods
	rsaKeyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	eddsaKeyPair, err := GenerateEdDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate EdDSA key pair: %v", err)
	}

	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test HMAC JWT
	hmacJWTResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "HMAC").
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create HMAC JWT: %v", err)
	}

	_, err = tm.ValidateJWTWithHMAC(hmacJWTResult.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate HMAC JWT: %v", err)
	}

	// Test RSA JWT
	rsaJWTResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "RSA").
		CreateJWTWithKeyPair(*rsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create RSA JWT: %v", err)
	}

	_, err = tm.ValidateJWTWithKeyPair(rsaJWTResult.Token, *rsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate RSA JWT: %v", err)
	}

	// Test ECDSA JWT
	ecdsaJWTResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "ECDSA").
		CreateJWTWithKeyPair(*ecdsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create ECDSA JWT: %v", err)
	}

	_, err = tm.ValidateJWTWithKeyPair(ecdsaJWTResult.Token, *ecdsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate ECDSA JWT: %v", err)
	}

	// Test EdDSA JWT
	eddsaJWTResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "EdDSA").
		CreateJWTWithKeyPair(*eddsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create EdDSA JWT: %v", err)
	}

	_, err = tm.ValidateJWTWithKeyPair(eddsaJWTResult.Token, *eddsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate EdDSA JWT: %v", err)
	}

	// Test HMAC Opaque
	hmacOpaqueResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "HMAC").
		CreateOpaqueWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create HMAC opaque token: %v", err)
	}

	_, err = tm.ValidateOpaqueWithHMAC(hmacOpaqueResult.Token, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to validate HMAC opaque token: %v", err)
	}

	// Test RSA Opaque
	rsaOpaqueResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "RSA").
		CreateOpaqueWithKeyPair(*rsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create RSA opaque token: %v", err)
	}

	_, err = tm.ValidateOpaqueWithKeyPair(rsaOpaqueResult.Token, *rsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate RSA opaque token: %v", err)
	}

	// Test ECDSA Opaque
	ecdsaOpaqueResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "ECDSA").
		CreateOpaqueWithKeyPair(*ecdsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create ECDSA opaque token: %v", err)
	}

	_, err = tm.ValidateOpaqueWithKeyPair(ecdsaOpaqueResult.Token, *ecdsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate ECDSA opaque token: %v", err)
	}

	// Test EdDSA Opaque
	eddsaOpaqueResult, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaim("method", "EdDSA").
		CreateOpaqueWithKeyPair(*eddsaKeyPair)

	if err != nil {
		t.Fatalf("Failed to create EdDSA opaque token: %v", err)
	}

	_, err = tm.ValidateOpaqueWithKeyPair(eddsaOpaqueResult.Token, *eddsaKeyPair)
	if err != nil {
		t.Fatalf("Failed to validate EdDSA opaque token: %v", err)
	}
}

func TestTokenBuilderErrorHandling(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test with invalid key pair
	invalidKeyPair := &KeyPair{
		Method:     "INVALID",
		PrivateKey: []byte("invalid"),
		PublicKey:  []byte("invalid"),
	}

	_, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		CreateJWTWithKeyPair(*invalidKeyPair)

	if err == nil {
		t.Error("Expected error for invalid key pair, got nil")
	}

	// Test with nil key pair
	_, err = tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		CreateJWTWithKeyPair(KeyPair{})

	if err == nil {
		t.Error("Expected error for nil key pair, got nil")
	}
}

func TestTokenBuilderPerformance(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test performance with many claims
	claims := make(map[string]interface{})
	for i := 0; i < 100; i++ {
		claims[fmt.Sprintf("claim_%d", i)] = fmt.Sprintf("value_%d", i)
	}

	start := time.Now()

	// Create token with many claims
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithClaims(claims).
		CreateJWTWithHMAC(SigningMethodHS256)

	duration := time.Since(start)

	if err != nil {
		t.Fatalf("Failed to create token with many claims: %v", err)
	}

	// Validate token
	_, err = tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate token with many claims: %v", err)
	}

	// Performance should be reasonable (less than 100ms for 100 claims)
	if duration > 100*time.Millisecond {
		t.Errorf("Token creation took too long: %v", duration)
	}
}

func TestTokenManagerBuilderEdgeCases(t *testing.T) {
	// Test builder with minimal configuration
	minimalTM := NewTokenManagerBuilder().Build()

	if minimalTM == nil {
		t.Fatal("Expected TokenManager, got nil")
	}

	// Test that defaults are set
	if minimalTM.config.DefaultExpiration != 24*time.Hour {
		t.Errorf("Expected default expiration 24h, got %v", minimalTM.config.DefaultExpiration)
	}

	if minimalTM.config.OpaqueTokenLength != 32 {
		t.Errorf("Expected default opaque token length 32, got %d", minimalTM.config.OpaqueTokenLength)
	}

	if minimalTM.config.JWTMethod != SigningMethodHS256 {
		t.Errorf("Expected default JWT method %s, got %s", SigningMethodHS256, minimalTM.config.JWTMethod)
	}

	// Test builder with all options
	fullTM := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		WithJWTMethod(SigningMethodHS512).
		WithDefaultExpiration(48 * time.Hour).
		WithOpaqueTokenLength(128).
		Build()

	if fullTM == nil {
		t.Fatal("Expected TokenManager, got nil")
	}

	// Test that all options are set
	if string(fullTM.config.JWTSecretKey) != "jwt-secret" {
		t.Errorf("Expected JWT secret 'jwt-secret', got '%s'", string(fullTM.config.JWTSecretKey))
	}

	if string(fullTM.config.OpaqueSecretKey) != "opaque-secret" {
		t.Errorf("Expected opaque secret 'opaque-secret', got '%s'", string(fullTM.config.OpaqueSecretKey))
	}

	if fullTM.config.JWTMethod != SigningMethodHS512 {
		t.Errorf("Expected JWT method %s, got %s", SigningMethodHS512, fullTM.config.JWTMethod)
	}

	if fullTM.config.DefaultExpiration != 48*time.Hour {
		t.Errorf("Expected default expiration 48h, got %v", fullTM.config.DefaultExpiration)
	}

	if fullTM.config.OpaqueTokenLength != 128 {
		t.Errorf("Expected opaque token length 128, got %d", fullTM.config.OpaqueTokenLength)
	}
}

func TestTokenBuilderChaining(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test method chaining with all methods
	result, err := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject").
		WithAudience("test-audience").
		WithExpirationDuration(2*time.Hour).
		WithNotBefore(time.Now()).
		WithIssuedAt(time.Now()).
		WithClaim("role", "admin").
		WithClaim("permissions", []string{"read", "write"}).
		WithClaims(map[string]interface{}{
			"department": "engineering",
			"level":      "senior",
		}).
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create token with full chaining: %v", err)
	}

	// Validate token
	validatedReq, err := tm.ValidateJWTToken(result.Token)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}

	// Check all fields
	if validatedReq.Issuer != "test-issuer" {
		t.Errorf("Expected issuer 'test-issuer', got '%s'", validatedReq.Issuer)
	}

	if validatedReq.Subject != "test-subject" {
		t.Errorf("Expected subject 'test-subject', got '%s'", validatedReq.Subject)
	}

	if validatedReq.Audience != "test-audience" {
		t.Errorf("Expected audience 'test-audience', got '%s'", validatedReq.Audience)
	}

	if validatedReq.CustomClaims["role"] != "admin" {
		t.Errorf("Expected role 'admin', got '%v'", validatedReq.CustomClaims["role"])
	}

	if validatedReq.CustomClaims["department"] != "engineering" {
		t.Errorf("Expected department 'engineering', got '%v'", validatedReq.CustomClaims["department"])
	}

	if validatedReq.CustomClaims["level"] != "senior" {
		t.Errorf("Expected level 'senior', got '%v'", validatedReq.CustomClaims["level"])
	}
}

func TestTokenBuilderReuse(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test reusing the same builder instance
	builder := tm.NewToken().
		WithIssuer("test-issuer").
		WithSubject("test-subject")

	// Create first token
	result1, err := builder.CreateJWTWithHMAC(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create first token: %v", err)
	}

	// Create second token with same builder
	result2, err := builder.
		WithClaim("role", "admin").
		CreateJWTWithHMAC(SigningMethodHS256)

	if err != nil {
		t.Fatalf("Failed to create second token: %v", err)
	}

	// Tokens should be different
	if result1.Token == result2.Token {
		t.Error("Expected different tokens, got same token")
	}

	// Validate both tokens
	_, err = tm.ValidateJWTToken(result1.Token)
	if err != nil {
		t.Fatalf("Failed to validate first token: %v", err)
	}

	_, err = tm.ValidateJWTToken(result2.Token)
	if err != nil {
		t.Fatalf("Failed to validate second token: %v", err)
	}
}

func TestTokenBuilderConcurrency(t *testing.T) {
	tm := NewTokenManagerBuilder().
		WithJWTSecret([]byte("jwt-secret")).
		WithOpaqueSecret([]byte("opaque-secret")).
		Build()

	// Test concurrent token creation
	const numGoroutines = 10
	results := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			result, err := tm.NewToken().
				WithIssuer(fmt.Sprintf("test-issuer-%d", id)).
				WithSubject(fmt.Sprintf("test-subject-%d", id)).
				WithClaim("id", id).
				CreateJWTWithHMAC(SigningMethodHS256)

			if err != nil {
				results <- err
				return
			}

			// Validate token
			_, err = tm.ValidateJWTToken(result.Token)
			results <- err
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Fatalf("Concurrent token creation failed: %v", err)
		}
	}
}

func TestOpaqueMethodConfiguration(t *testing.T) {
	// Test different opaque methods
	methods := []SigningMethod{
		SigningMethodHS256,
		SigningMethodHS384,
		SigningMethodHS512,
	}

	for _, method := range methods {
		t.Run(string(method), func(t *testing.T) {
			// Create TokenManager with specific opaque method
			tm := NewTokenManager(&TokenManagerConfig{
				OpaqueSecretKey:   []byte("test-opaque-secret"),
				OpaqueMethod:      method,
				DefaultExpiration: time.Hour,
			})

			// Create opaque token
			req := TokenRequest{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				ExpiresAt: time.Now().Add(time.Hour),
				IssuedAt:  time.Now(),
			}

			result, err := tm.CreateOpaqueToken(req)
			if err != nil {
				t.Fatalf("Failed to create opaque token: %v", err)
			}

			// Validate the token
			validatedReq, err := tm.ValidateOpaqueToken(result.Token)
			if err != nil {
				t.Fatalf("Failed to validate opaque token: %v", err)
			}

			// Verify the token data
			if validatedReq.Issuer != req.Issuer {
				t.Errorf("Expected issuer %s, got %s", req.Issuer, validatedReq.Issuer)
			}
			if validatedReq.Subject != req.Subject {
				t.Errorf("Expected subject %s, got %s", req.Subject, validatedReq.Subject)
			}
		})
	}
}

func TestOpaqueMethodWithBuilder(t *testing.T) {
	// Test OpaqueMethod with TokenManagerBuilder
	tm := NewTokenManagerBuilder().
		WithOpaqueSecret([]byte("builder-opaque-secret")).
		Build()

	// Create opaque token using TokenBuilder with specific method
	result, err := tm.NewToken().
		WithIssuer("builder-issuer").
		WithSubject("builder-subject").
		WithClaim("test", "value").
		CreateOpaqueWithHMAC(SigningMethodHS512)

	if err != nil {
		t.Fatalf("Failed to create opaque token with builder: %v", err)
	}

	// Validate the token
	validatedReq, err := tm.ValidateOpaqueWithHMAC(result.Token, SigningMethodHS512)
	if err != nil {
		t.Fatalf("Failed to validate opaque token: %v", err)
	}

	// Verify the token data
	if validatedReq.Issuer != "builder-issuer" {
		t.Errorf("Expected issuer builder-issuer, got %s", validatedReq.Issuer)
	}
	if validatedReq.Subject != "builder-subject" {
		t.Errorf("Expected subject builder-subject, got %s", validatedReq.Subject)
	}
	if validatedReq.CustomClaims["test"] != "value" {
		t.Errorf("Expected custom claim test=value, got %v", validatedReq.CustomClaims["test"])
	}
}
