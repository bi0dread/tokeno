package tokeno

import (
	"crypto/elliptic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateJwtTokenWithMethod(t *testing.T) {
	secretKey := []byte("test-secret-key")
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

	tests := []struct {
		name        string
		method      SigningMethod
		key         interface{}
		expectError bool
	}{
		{
			name:        "HMAC HS256",
			method:      SigningMethodHS256,
			key:         secretKey,
			expectError: false,
		},
		{
			name:        "HMAC HS384",
			method:      SigningMethodHS384,
			key:         secretKey,
			expectError: false,
		},
		{
			name:        "HMAC HS512",
			method:      SigningMethodHS512,
			key:         secretKey,
			expectError: false,
		},
		{
			name:        "Invalid method",
			method:      "INVALID",
			key:         secretKey,
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := CreateJwtTokenWithMethod(tokenReq, tt.key, tt.method)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				// Verify the token can be parsed
				parsedToken, err := ParseJwtTokenWithMethod(tokenString, tt.key, tt.method)
				if err != nil {
					t.Errorf("Failed to parse generated token: %v", err)
				}

				// Validate token claims
				if err := ValidateTokenClaims(parsedToken); err != nil {
					t.Errorf("Token validation failed: %v", err)
				}
			}
		})
	}
}

func TestGenerateRSAKeyPair(t *testing.T) {
	tests := []struct {
		name        string
		bits        int
		expectError bool
	}{
		{
			name:        "RSA 2048 bits",
			bits:        2048,
			expectError: false,
		},
		{
			name:        "RSA 3072 bits",
			bits:        3072,
			expectError: false,
		},
		{
			name:        "RSA 4096 bits",
			bits:        4096,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateRSAKeyPair(tt.bits)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				if keyPair == nil {
					t.Error("KeyPair should not be nil")
				}
				if keyPair.PrivateKey == nil {
					t.Error("PrivateKey should not be nil")
				}
				if keyPair.PublicKey == nil {
					t.Error("PublicKey should not be nil")
				}

				// Test creating and parsing a token with the key pair
				now := time.Now()
				tokenReq := TokenRequest{
					Issuer:    "test-issuer",
					Subject:   "test-subject",
					Audience:  "test-audience",
					ExpiresAt: now.Add(time.Hour),
					NotBefore: now,
					IssuedAt:  now,
				}

				tokenString, err := CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
				if err != nil {
					t.Errorf("Failed to create token with RSA key pair: %v", err)
				}

				parsedToken, err := ParseJwtTokenWithKeyPair(tokenString, *keyPair)
				if err != nil {
					t.Errorf("Failed to parse token with RSA key pair: %v", err)
				}

				if err := ValidateTokenClaims(parsedToken); err != nil {
					t.Errorf("Token validation failed: %v", err)
				}
			}
		})
	}
}

func TestGenerateECDSAKeyPair(t *testing.T) {
	tests := []struct {
		name        string
		curve       elliptic.Curve
		expectError bool
	}{
		{
			name:        "ECDSA P-256",
			curve:       elliptic.P256(),
			expectError: false,
		},
		{
			name:        "ECDSA P-384",
			curve:       elliptic.P384(),
			expectError: false,
		},
		{
			name:        "ECDSA P-521",
			curve:       elliptic.P521(),
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := GenerateECDSAKeyPair(tt.curve)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				if keyPair == nil {
					t.Error("KeyPair should not be nil")
				}
				if keyPair.PrivateKey == nil {
					t.Error("PrivateKey should not be nil")
				}
				if keyPair.PublicKey == nil {
					t.Error("PublicKey should not be nil")
				}

				// Test creating and parsing a token with the key pair
				now := time.Now()
				tokenReq := TokenRequest{
					Issuer:    "test-issuer",
					Subject:   "test-subject",
					Audience:  "test-audience",
					ExpiresAt: now.Add(time.Hour),
					NotBefore: now,
					IssuedAt:  now,
				}

				tokenString, err := CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
				if err != nil {
					t.Errorf("Failed to create token with ECDSA key pair: %v", err)
				}

				parsedToken, err := ParseJwtTokenWithKeyPair(tokenString, *keyPair)
				if err != nil {
					t.Errorf("Failed to parse token with ECDSA key pair: %v", err)
				}

				if err := ValidateTokenClaims(parsedToken); err != nil {
					t.Errorf("Token validation failed: %v", err)
				}
			}
		})
	}
}

func TestGenerateEdDSAKeyPair(t *testing.T) {
	keyPair, err := GenerateEdDSAKeyPair()

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	if keyPair == nil {
		t.Error("KeyPair should not be nil")
	}
	if keyPair.PrivateKey == nil {
		t.Error("PrivateKey should not be nil")
	}
	if keyPair.PublicKey == nil {
		t.Error("PublicKey should not be nil")
	}

	// Test creating and parsing a token with the key pair
	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	tokenString, err := CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
	if err != nil {
		t.Errorf("Failed to create token with EdDSA key pair: %v", err)
	}

	parsedToken, err := ParseJwtTokenWithKeyPair(tokenString, *keyPair)
	if err != nil {
		t.Errorf("Failed to parse token with EdDSA key pair: %v", err)
	}

	if err := ValidateTokenClaims(parsedToken); err != nil {
		t.Errorf("Token validation failed: %v", err)
	}
}

func TestParseJwtTokenWithMethod(t *testing.T) {
	secretKey := []byte("test-secret-key")
	now := time.Now()

	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	tokenString, err := CreateJwtTokenWithMethod(tokenReq, secretKey, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Test valid token parsing
	parsedToken, err := ParseJwtTokenWithMethod(tokenString, secretKey, SigningMethodHS256)
	if err != nil {
		t.Errorf("Failed to parse valid token: %v", err)
	}

	if parsedToken == nil {
		t.Error("Parsed token should not be nil")
	}

	// Test invalid token parsing
	invalidToken := "invalid.jwt.token"
	_, err = ParseJwtTokenWithMethod(invalidToken, secretKey, SigningMethodHS256)
	if err == nil {
		t.Error("Expected error for invalid token, but got none")
	}

	// Test token with wrong method
	_, err = ParseJwtTokenWithMethod(tokenString, secretKey, SigningMethodHS384)
	if err == nil {
		t.Error("Expected error for token with wrong method, but got none")
	}
}

func TestSigningMethodConstants(t *testing.T) {
	// Test that all signing method constants are defined
	expectedMethods := []SigningMethod{
		SigningMethodHS256, SigningMethodHS384, SigningMethodHS512,
		SigningMethodRS256, SigningMethodRS384, SigningMethodRS512,
		SigningMethodES256, SigningMethodES384, SigningMethodES512,
		SigningMethodEdDSA,
	}

	for _, method := range expectedMethods {
		if method == "" {
			t.Errorf("Signing method constant should not be empty")
		}
	}
}

func TestKeyPairStructure(t *testing.T) {
	// Test RSA key pair
	rsaKeyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	if rsaKeyPair.Method != SigningMethodRS256 {
		t.Errorf("Expected method RS256, got %s", rsaKeyPair.Method)
	}

	// Test ECDSA key pair
	ecdsaKeyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	if ecdsaKeyPair.Method != SigningMethodES256 {
		t.Errorf("Expected method ES256, got %s", ecdsaKeyPair.Method)
	}

	// Test EdDSA key pair
	eddsaKeyPair, err := GenerateEdDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate EdDSA key pair: %v", err)
	}

	if eddsaKeyPair.Method != SigningMethodEdDSA {
		t.Errorf("Expected method EdDSA, got %s", eddsaKeyPair.Method)
	}
}

func TestCrossMethodCompatibility(t *testing.T) {
	// Test that tokens created with one method cannot be parsed with another
	secretKey := []byte("test-secret-key")
	now := time.Now()

	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	// Create token with HS256
	hs256Token, err := CreateJwtTokenWithMethod(tokenReq, secretKey, SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to create HS256 token: %v", err)
	}

	// Try to parse with HS384 (should fail)
	_, err = ParseJwtTokenWithMethod(hs256Token, secretKey, SigningMethodHS384)
	if err == nil {
		t.Error("Expected error when parsing HS256 token with HS384 method")
	}

	// Try to parse with correct method (should succeed)
	_, err = ParseJwtTokenWithMethod(hs256Token, secretKey, SigningMethodHS256)
	if err != nil {
		t.Errorf("Unexpected error when parsing HS256 token with correct method: %v", err)
	}
}

func TestTokenRequestWithAllMethods(t *testing.T) {
	now := time.Now()
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role":     "admin",
			"user_id":  123,
			"features": []string{"read", "write"},
		},
	}

	// Test HMAC
	secretKey := []byte("test-secret-key")
	hmacToken, err := CreateJwtTokenWithMethod(tokenReq, secretKey, SigningMethodHS256)
	if err != nil {
		t.Errorf("Failed to create HMAC token: %v", err)
	}

	// Test RSA
	rsaKeyPair, err := GenerateRSAKeyPair(2048)
	if err != nil {
		t.Fatalf("Failed to generate RSA key pair: %v", err)
	}
	rsaToken, err := CreateJwtTokenWithKeyPair(tokenReq, *rsaKeyPair)
	if err != nil {
		t.Errorf("Failed to create RSA token: %v", err)
	}

	// Test ECDSA
	ecdsaKeyPair, err := GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		t.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}
	ecdsaToken, err := CreateJwtTokenWithKeyPair(tokenReq, *ecdsaKeyPair)
	if err != nil {
		t.Errorf("Failed to create ECDSA token: %v", err)
	}

	// Test EdDSA
	eddsaKeyPair, err := GenerateEdDSAKeyPair()
	if err != nil {
		t.Fatalf("Failed to generate EdDSA key pair: %v", err)
	}
	eddsaToken, err := CreateJwtTokenWithKeyPair(tokenReq, *eddsaKeyPair)
	if err != nil {
		t.Errorf("Failed to create EdDSA token: %v", err)
	}

	// Verify all tokens are different
	tokens := []string{hmacToken, rsaToken, ecdsaToken, eddsaToken}
	for i := 0; i < len(tokens); i++ {
		for j := i + 1; j < len(tokens); j++ {
			if tokens[i] == tokens[j] {
				t.Errorf("Tokens %d and %d are identical, they should be different", i, j)
			}
		}
	}

	// Verify all tokens can be parsed and validated
	tokenKeyPairs := []struct {
		token   string
		keyPair *KeyPair
		method  SigningMethod
		key     interface{}
	}{
		{hmacToken, nil, SigningMethodHS256, secretKey},
		{rsaToken, rsaKeyPair, SigningMethodRS256, nil},
		{ecdsaToken, ecdsaKeyPair, SigningMethodES256, nil},
		{eddsaToken, eddsaKeyPair, SigningMethodEdDSA, nil},
	}

	for i, tkp := range tokenKeyPairs {
		var parsedToken *jwt.Token
		var err error

		if tkp.keyPair != nil {
			parsedToken, err = ParseJwtTokenWithKeyPair(tkp.token, *tkp.keyPair)
		} else {
			parsedToken, err = ParseJwtTokenWithMethod(tkp.token, tkp.key, tkp.method)
		}

		if err != nil {
			t.Errorf("Failed to parse token %d: %v", i, err)
			continue
		}

		if err := ValidateTokenClaims(parsedToken); err != nil {
			t.Errorf("Token validation failed for token %d: %v", i, err)
		}
	}
}
