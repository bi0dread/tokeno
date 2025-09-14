package main

import (
	"crypto/elliptic"
	"fmt"
	"log"
	"time"

	"github.com/bi0dread/tokeno"
)

func main() {
	fmt.Println("=== Tokeno - JWT & Opaque Token Examples ===")

	// Create TokenManager configuration
	config := &tokeno.TokenManagerConfig{
		JWTSecretKey:      []byte("your-jwt-secret-key-here"),
		OpaqueSecretKey:   []byte("your-opaque-secret-key-here"),
		OpaqueTokenLength: 32,
		DefaultExpiration: 24 * time.Hour,
	}

	// Create TokenManager
	tm := tokeno.NewTokenManager(config)

	// Common token request
	now := time.Now()
	tokenReq := tokeno.TokenRequest{
		Issuer:    "tokeno-service",
		Subject:   "user123",
		Audience:  "api-clients",
		ExpiresAt: now.Add(24 * time.Hour),
		NotBefore: now,
		IssuedAt:  now,
		CustomClaims: map[string]interface{}{
			"role":     "admin",
			"user_id":  123,
			"features": []string{"read", "write", "delete"},
		},
	}

	// Example 1: JWT Token with HMAC
	fmt.Println("\n1. JWT Token (HMAC) Example:")
	fmt.Println("=============================")

	jwtResult, err := tm.CreateJWTToken(tokenReq)
	if err != nil {
		log.Fatalf("Failed to create JWT token: %v", err)
	}

	fmt.Printf("JWT Token: %s\n", jwtResult.Token)
	fmt.Printf("Type: %s\n", jwtResult.Type)
	fmt.Printf("Expires At: %s\n", jwtResult.ExpiresAt.Format(time.RFC3339))

	// Validate JWT token
	validatedJWT, err := tm.ValidateJWTToken(jwtResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate JWT token: %v", err)
	}
	fmt.Printf("✓ JWT Token is valid! (Issuer: %s, Subject: %s)\n", validatedJWT.Issuer, validatedJWT.Subject)

	// Example 2: Opaque Token
	fmt.Println("\n2. Opaque Token Example:")
	fmt.Println("========================")

	opaqueResult, err := tm.CreateOpaqueToken(tokenReq)
	if err != nil {
		log.Fatalf("Failed to create opaque token: %v", err)
	}

	fmt.Printf("Opaque Token: %s\n", opaqueResult.Token)
	fmt.Printf("Type: %s\n", opaqueResult.Type)
	fmt.Printf("Expires At: %s\n", opaqueResult.ExpiresAt.Format(time.RFC3339))

	// Validate opaque token
	validatedOpaque, err := tm.ValidateOpaqueToken(opaqueResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate opaque token: %v", err)
	}
	fmt.Printf("✓ Opaque Token is valid! (Issuer: %s, Subject: %s)\n", validatedOpaque.Issuer, validatedOpaque.Subject)

	// Example 3: Auto-detection of token type
	fmt.Println("\n3. Auto Token Type Detection:")
	fmt.Println("=============================")

	// Validate JWT token using auto-detection
	autoValidatedJWT, err := tm.ValidateToken(jwtResult.Token)
	if err != nil {
		log.Fatalf("Failed to auto-validate JWT token: %v", err)
	}
	fmt.Printf("✓ Auto-detected JWT token validated! (Role: %v)\n", autoValidatedJWT.CustomClaims["role"])

	// Validate opaque token using auto-detection
	autoValidatedOpaque, err := tm.ValidateToken(opaqueResult.Token)
	if err != nil {
		log.Fatalf("Failed to auto-validate opaque token: %v", err)
	}
	fmt.Printf("✓ Auto-detected opaque token validated! (Role: %v)\n", autoValidatedOpaque.CustomClaims["role"])

	// Example 4: JWT with RSA Key Pair
	fmt.Println("\n4. JWT Token with RSA Key Pair:")
	fmt.Println("===============================")

	// Generate RSA key pair for JWT
	jwtRSAKeyPair, err := tokeno.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	// Create TokenManager with RSA key pair for JWT
	jwtRSAConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey:      []byte("your-jwt-secret-key-here"),
		OpaqueSecretKey:   []byte("your-opaque-secret-key-here"),
		JWTKeyPair:        jwtRSAKeyPair,
		DefaultExpiration: 24 * time.Hour,
	}

	jwtRSATM := tokeno.NewTokenManager(jwtRSAConfig)

	// Create JWT token with RSA
	jwtRSAResult, err := jwtRSATM.CreateJWTToken(tokenReq)
	if err != nil {
		log.Fatalf("Failed to create RSA JWT token: %v", err)
	}

	fmt.Printf("RSA JWT Token: %s\n", jwtRSAResult.Token[:50]+"...")

	// Validate RSA JWT token
	_, err = jwtRSATM.ValidateJWTToken(jwtRSAResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate RSA JWT token: %v", err)
	}
	fmt.Printf("✓ RSA JWT Token is valid! (Method: %s)\n", jwtRSAKeyPair.Method)

	// Example 5: Explicit HMAC Functions
	fmt.Println("\n5. Explicit HMAC Functions:")
	fmt.Println("===========================")

	// Create TokenManager for HMAC-only operations
	hmacConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey:      []byte("your-jwt-secret-key-here"),
		OpaqueSecretKey:   []byte("your-opaque-secret-key-here"),
		DefaultExpiration: 24 * time.Hour,
	}

	hmacTM := tokeno.NewTokenManager(hmacConfig)

	// Create JWT token with explicit HMAC using TokenBuilder
	jwtHMACResult, err := hmacTM.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create JWT token with HMAC: %v", err)
	}

	fmt.Printf("JWT HMAC Token: %s\n", jwtHMACResult.Token[:50]+"...")

	// Validate JWT token with explicit HMAC using TokenBuilder
	_, err = hmacTM.ValidateJWTWithHMAC(jwtHMACResult.Token, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate JWT token with HMAC: %v", err)
	}
	fmt.Printf("✓ JWT HMAC Token is valid!\n")

	// Create opaque token with explicit HMAC using TokenBuilder
	opaqueHMACResult, err := hmacTM.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create opaque token with HMAC: %v", err)
	}

	fmt.Printf("Opaque HMAC Token: %s\n", opaqueHMACResult.Token[:50]+"...")

	// Validate opaque token with explicit HMAC using TokenBuilder
	_, err = hmacTM.ValidateOpaqueWithHMAC(opaqueHMACResult.Token, tokeno.SigningMethodHS256)
	if err != nil {
		log.Fatalf("Failed to validate opaque token with HMAC: %v", err)
	}
	fmt.Printf("✓ Opaque HMAC Token is valid!\n")

	// Example 6: Explicit Key Pair Functions
	fmt.Println("\n6. Explicit Key Pair Functions:")
	fmt.Println("===============================")

	// Generate RSA key pair for explicit operations
	explicitRSAKeyPair, err := tokeno.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair for explicit operations: %v", err)
	}

	// Create TokenManager for explicit key pair operations
	explicitConfig := &tokeno.TokenManagerConfig{
		JWTSecretKey:      []byte("your-jwt-secret-key-here"),
		OpaqueSecretKey:   []byte("your-opaque-secret-key-here"),
		DefaultExpiration: 24 * time.Hour,
	}

	explicitTM := tokeno.NewTokenManager(explicitConfig)

	// Create JWT token with explicit key pair using TokenBuilder
	jwtKeyPairResult, err := explicitTM.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateJWTWithKeyPair(*explicitRSAKeyPair)

	if err != nil {
		log.Fatalf("Failed to create JWT token with explicit key pair: %v", err)
	}

	fmt.Printf("JWT Key Pair Token: %s\n", jwtKeyPairResult.Token[:50]+"...")

	// Validate JWT token with explicit key pair using TokenBuilder
	_, err = explicitTM.ValidateJWTWithKeyPair(jwtKeyPairResult.Token, *explicitRSAKeyPair)
	if err != nil {
		log.Fatalf("Failed to validate JWT token with explicit key pair: %v", err)
	}
	fmt.Printf("✓ JWT Key Pair Token is valid! (Method: %s)\n", explicitRSAKeyPair.Method)

	// Create opaque token with explicit key pair using TokenBuilder
	opaqueKeyPairResult, err := explicitTM.NewToken().
		WithIssuer(tokenReq.Issuer).
		WithSubject(tokenReq.Subject).
		WithAudience(tokenReq.Audience).
		WithExpiration(tokenReq.ExpiresAt).
		WithNotBefore(tokenReq.NotBefore).
		WithIssuedAt(tokenReq.IssuedAt).
		WithClaims(tokenReq.CustomClaims).
		CreateOpaqueWithKeyPair(*explicitRSAKeyPair)

	if err != nil {
		log.Fatalf("Failed to create opaque token with explicit key pair: %v", err)
	}

	fmt.Printf("Opaque Key Pair Token: %s\n", opaqueKeyPairResult.Token[:50]+"...")

	// Validate opaque token with explicit key pair using TokenBuilder
	_, err = explicitTM.ValidateOpaqueWithKeyPair(opaqueKeyPairResult.Token, *explicitRSAKeyPair)
	if err != nil {
		log.Fatalf("Failed to validate opaque token with explicit key pair: %v", err)
	}
	fmt.Printf("✓ Opaque Key Pair Token is valid! (Method: %s)\n", explicitRSAKeyPair.Method)

	// Example 7: Token comparison and claims
	fmt.Println("\n7. Token Claims Comparison:")
	fmt.Println("===========================")

	fmt.Println("JWT Token Claims:")
	claims := validatedJWT.CustomClaims
	for key, value := range claims {
		fmt.Printf("  %s: %v\n", key, value)
	}

	fmt.Println("\nOpaque Token Claims:")
	opaqueClaims := validatedOpaque.CustomClaims
	for key, value := range opaqueClaims {
		fmt.Printf("  %s: %v\n", key, value)
	}

	// Example 8: Builder Pattern Examples
	fmt.Println("\n8. Builder Pattern Examples:")
	fmt.Println("=============================")

	// Create TokenManager using builder pattern
	builderTM := tokeno.NewTokenManagerBuilder().
		WithJWTSecret([]byte("builder-jwt-secret")).
		WithOpaqueSecret([]byte("builder-opaque-secret")).
		WithJWTMethod(tokeno.SigningMethodHS512).
		WithDefaultExpiration(12 * time.Hour).
		WithOpaqueTokenLength(64).
		Build()

	fmt.Println("✓ TokenManager created with builder pattern")

	// Create JWT token using method chaining
	jwtBuilderResult, err := builderTM.NewToken().
		WithIssuer("builder-service").
		WithSubject("builder-user").
		WithAudience("builder-clients").
		WithExpirationDuration(6*time.Hour).
		WithClaim("role", "builder-admin").
		WithClaim("permissions", []string{"create", "read", "update", "delete"}).
		WithClaim("department", "engineering").
		CreateJWTWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create JWT with builder: %v", err)
	}

	fmt.Printf("JWT Builder Token: %s\n", jwtBuilderResult.Token[:50]+"...")

	// Validate JWT token
	_, err = builderTM.ValidateJWTToken(jwtBuilderResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate JWT builder token: %v", err)
	}
	fmt.Printf("✓ JWT Builder Token is valid!\n")

	// Create opaque token using method chaining
	opaqueBuilderResult, err := builderTM.NewToken().
		WithIssuer("builder-service").
		WithSubject("builder-user").
		WithAudience("builder-clients").
		WithExpirationDuration(6*time.Hour).
		WithClaim("role", "builder-user").
		WithClaim("features", []string{"analytics", "reporting"}).
		WithClaim("tier", "premium").
		CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create opaque token with builder: %v", err)
	}

	fmt.Printf("Opaque Builder Token: %s\n", opaqueBuilderResult.Token[:50]+"...")

	// Validate opaque token
	_, err = builderTM.ValidateOpaqueToken(opaqueBuilderResult.Token)
	if err != nil {
		log.Fatalf("Failed to validate opaque builder token: %v", err)
	}
	fmt.Printf("✓ Opaque Builder Token is valid!\n")

	// Example 9: Advanced Builder with Key Pairs
	fmt.Println("\n9. Advanced Builder with Key Pairs:")
	fmt.Println("===================================")

	// Generate key pairs
	rsaKeyPair, err := tokeno.GenerateRSAKeyPair(2048)
	if err != nil {
		log.Fatalf("Failed to generate RSA key pair: %v", err)
	}

	ecdsaKeyPair, err := tokeno.GenerateECDSAKeyPair(elliptic.P256())
	if err != nil {
		log.Fatalf("Failed to generate ECDSA key pair: %v", err)
	}

	// Create advanced TokenManager
	advancedTM := tokeno.NewTokenManagerBuilder().
		WithJWTSecret([]byte("advanced-jwt-secret")).
		WithOpaqueSecret([]byte("advanced-opaque-secret")).
		WithJWTKeyPair(rsaKeyPair).
		WithOpaqueKeyPair(ecdsaKeyPair).
		WithDefaultExpiration(8 * time.Hour).
		Build()

	fmt.Println("✓ Advanced TokenManager created with key pairs")

	// Create JWT with explicit key pair using builder
	advancedJWTResult, err := advancedTM.NewToken().
		WithIssuer("advanced-service").
		WithSubject("advanced-user").
		WithAudience("advanced-clients").
		WithExpirationDuration(4*time.Hour).
		WithClaim("role", "advanced-admin").
		WithClaim("security_level", "high").
		WithClaim("mfa_enabled", true).
		CreateJWTWithKeyPair(*rsaKeyPair)

	if err != nil {
		log.Fatalf("Failed to create advanced JWT: %v", err)
	}

	fmt.Printf("Advanced JWT Token: %s\n", advancedJWTResult.Token[:50]+"...")

	// Validate JWT with key pair using TokenBuilder
	_, err = advancedTM.ValidateJWTWithKeyPair(advancedJWTResult.Token, *rsaKeyPair)
	if err != nil {
		log.Fatalf("Failed to validate advanced JWT: %v", err)
	}
	fmt.Printf("✓ Advanced JWT Token is valid! (Method: %s)\n", rsaKeyPair.Method)

	// Create opaque token with explicit key pair using builder
	advancedOpaqueResult, err := advancedTM.NewToken().
		WithIssuer("advanced-service").
		WithSubject("advanced-user").
		WithAudience("advanced-clients").
		WithExpirationDuration(4*time.Hour).
		WithClaim("role", "advanced-user").
		WithClaim("security_level", "medium").
		WithClaim("api_access", true).
		CreateOpaqueWithKeyPair(*ecdsaKeyPair)

	if err != nil {
		log.Fatalf("Failed to create advanced opaque token: %v", err)
	}

	fmt.Printf("Advanced Opaque Token: %s\n", advancedOpaqueResult.Token[:50]+"...")

	// Validate opaque token with key pair using TokenBuilder
	_, err = advancedTM.ValidateOpaqueWithKeyPair(advancedOpaqueResult.Token, *ecdsaKeyPair)
	if err != nil {
		log.Fatalf("Failed to validate advanced opaque token: %v", err)
	}
	fmt.Printf("✓ Advanced Opaque Token is valid! (Method: %s)\n", ecdsaKeyPair.Method)

	// Example 10: Opaque Token with Different HMAC Methods
	fmt.Println("\n10. Opaque Token with Different HMAC Methods:")
	fmt.Println("==============================================")

	// Test different HMAC methods for opaque tokens
	hmacMethods := []tokeno.SigningMethod{tokeno.SigningMethodHS256, tokeno.SigningMethodHS384, tokeno.SigningMethodHS512}

	for i, method := range hmacMethods {
		fmt.Printf("\n--- Testing %s ---\n", method)

		// Create TokenManager with specific opaque method
		methodTM := tokeno.NewTokenManagerBuilder().
			WithOpaqueSecret([]byte("method-specific-secret")).
			Build()

		// Create opaque token
		methodResult, err := methodTM.NewToken().
			WithIssuer("method-issuer").
			WithSubject("method-user").
			WithClaim("method", string(method)).
			WithClaim("test_id", i+1).
			CreateOpaqueWithHMAC(method)

		if err != nil {
			fmt.Printf("❌ Failed to create opaque token with %s: %v\n", method, err)
			continue
		}

		fmt.Printf("Opaque Token (%s): %s\n", method, methodResult.Token[:50]+"...")

		// Validate the token
		validatedReq, err := methodTM.ValidateOpaqueWithHMAC(methodResult.Token, method)
		if err != nil {
			fmt.Printf("❌ Failed to validate opaque token with %s: %v\n", method, err)
		} else {
			fmt.Printf("✓ Opaque token with %s is valid! (Method: %s, Test ID: %v)\n",
				method, validatedReq.CustomClaims["method"], validatedReq.CustomClaims["test_id"])
		}
	}

	// Example 11: Token expiration handling
	fmt.Println("\n11. Token Expiration Example:")
	fmt.Println("=============================")

	// Create a token that expires in 1 second using builder
	shortResult, err := tm.NewToken().
		WithIssuer("test-service").
		WithSubject("test-user").
		WithAudience("api-clients").
		WithExpirationDuration(1*time.Second).
		WithClaim("role", "user").
		CreateOpaqueWithHMAC(tokeno.SigningMethodHS256)

	if err != nil {
		log.Fatalf("Failed to create short-lived token: %v", err)
	}

	fmt.Printf("Created short-lived token (expires in 1 second)\n")
	fmt.Printf("Token: %s\n", shortResult.Token[:50]+"...")

	// Wait for token to expire
	fmt.Println("Waiting for token to expire...")
	time.Sleep(2 * time.Second)

	// Try to validate expired token
	_, err = tm.ValidateOpaqueToken(shortResult.Token)
	if err != nil {
		fmt.Printf("✓ Token correctly expired: %v\n", err)
	} else {
		fmt.Println("✗ Token should have expired but didn't")
	}

	fmt.Println("\n=== All TokenManager examples completed successfully! ===")
}
