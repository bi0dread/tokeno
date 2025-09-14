package tokeno

import (
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestCreateJwtToken(t *testing.T) {
	secretKey := []byte("test-secret-key")
	now := time.Now()

	tests := []struct {
		name        string
		tokenReq    TokenRequest
		expectError bool
	}{
		{
			name: "Valid token request",
			tokenReq: TokenRequest{
				Issuer:    "test-issuer",
				Subject:   "test-subject",
				Audience:  "test-audience",
				ExpiresAt: now.Add(time.Hour),
				NotBefore: now,
				IssuedAt:  now,
				CustomClaims: map[string]interface{}{
					"role": "user",
				},
			},
			expectError: false,
		},
		{
			name: "Token request with custom claims",
			tokenReq: TokenRequest{
				Issuer:    "my-app",
				Subject:   "user123",
				Audience:  "api",
				ExpiresAt: now.Add(24 * time.Hour),
				NotBefore: now,
				IssuedAt:  now,
				CustomClaims: map[string]interface{}{
					"user_id":     123,
					"role":        "admin",
					"permissions": []string{"read", "write"},
				},
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenString, err := CreateJwtToken(tt.tokenReq, secretKey)

			if tt.expectError && err == nil {
				t.Errorf("Expected error but got none")
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}

			if !tt.expectError {
				// Verify the token can be parsed
				parsedToken, err := ParseJwtToken(tokenString, secretKey)
				if err != nil {
					t.Errorf("Failed to parse generated token: %v", err)
				}

				// Validate token claims
				if err := ValidateTokenClaims(parsedToken); err != nil {
					t.Errorf("Token validation failed: %v", err)
				}

				// Check if custom claims are present
				claims := parsedToken.Claims.(jwt.MapClaims)
				for key, expectedValue := range tt.tokenReq.CustomClaims {
					if actualValue, exists := claims[key]; !exists {
						t.Errorf("Custom claim %s not found in token", key)
					} else {
						// JWT converts numbers to float64, so we need special handling
						switch key {
						case "permissions":
							// For slices, compare as strings
							expectedSlice, ok := expectedValue.([]string)
							if ok {
								expectedInterface := make([]interface{}, len(expectedSlice))
								for i, v := range expectedSlice {
									expectedInterface[i] = v
								}
								if fmt.Sprintf("%v", actualValue) != fmt.Sprintf("%v", expectedInterface) {
									t.Errorf("Custom claim %s: expected %v, got %v", key, expectedInterface, actualValue)
								}
							}
						case "user_id":
							// JWT converts int to float64
							if expectedInt, ok := expectedValue.(int); ok {
								if actualFloat, ok := actualValue.(float64); ok {
									if int(actualFloat) != expectedInt {
										t.Errorf("Custom claim %s: expected %v, got %v", key, expectedInt, int(actualFloat))
									}
								} else {
									t.Errorf("Custom claim %s: expected int, got %T", key, actualValue)
								}
							}
						default:
							if actualValue != expectedValue {
								t.Errorf("Custom claim %s: expected %v, got %v", key, expectedValue, actualValue)
							}
						}
					}
				}
			}
		})
	}
}

func TestParseJwtToken(t *testing.T) {
	secretKey := []byte("test-secret-key")
	now := time.Now()

	// Create a valid token
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

	tokenString, err := CreateJwtToken(tokenReq, secretKey)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Test valid token parsing
	parsedToken, err := ParseJwtToken(tokenString, secretKey)
	if err != nil {
		t.Errorf("Failed to parse valid token: %v", err)
	}

	if parsedToken == nil {
		t.Error("Parsed token should not be nil")
	}

	// Test invalid token parsing
	invalidToken := "invalid.jwt.token"
	_, err = ParseJwtToken(invalidToken, secretKey)
	if err == nil {
		t.Error("Expected error for invalid token, but got none")
	}

	// Test token with wrong secret
	wrongSecret := []byte("wrong-secret")
	_, err = ParseJwtToken(tokenString, wrongSecret)
	if err == nil {
		t.Error("Expected error for token with wrong secret, but got none")
	}
}

func TestValidateTokenClaims(t *testing.T) {
	secretKey := []byte("test-secret-key")
	now := time.Now()

	// Create a valid token
	tokenReq := TokenRequest{
		Issuer:    "test-issuer",
		Subject:   "test-subject",
		Audience:  "test-audience",
		ExpiresAt: now.Add(time.Hour),
		NotBefore: now,
		IssuedAt:  now,
	}

	tokenString, err := CreateJwtToken(tokenReq, secretKey)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	parsedToken, err := ParseJwtToken(tokenString, secretKey)
	if err != nil {
		t.Fatalf("Failed to parse test token: %v", err)
	}

	// Test valid token
	err = ValidateTokenClaims(parsedToken)
	if err != nil {
		t.Errorf("Valid token should pass validation: %v", err)
	}

	// Test invalid token (manually create one with missing claims)
	invalidToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": "test-issuer",
		// Missing other required claims
	})

	err = ValidateTokenClaims(invalidToken)
	if err == nil {
		t.Error("Expected validation error for token with missing claims")
	}
}
