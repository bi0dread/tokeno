package tokeno

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"io/ioutil"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ed25519"
)

// TokenType represents the type of token
type TokenType string

const (
	TokenTypeJWT TokenType = "jwt"
)

// TokenRefreshConfig holds configuration for token refresh functionality
type TokenRefreshConfig struct {
	RefreshThreshold   time.Duration // When to start refreshing (e.g., 1 hour before expiry)
	MaxRefreshAttempts int           // Maximum refresh attempts
	RefreshGracePeriod time.Duration // Grace period for refresh
	RefreshTokenLength int           // Length of refresh token (default: 64)
	RefreshTokenExpiry time.Duration // Refresh token expiration (default: 7 days)
}

// TokenManagerConfig holds configuration for the TokenManager
type TokenManagerConfig struct {
	// JWT Configuration
	JWTSecretKey []byte
	JWTMethod    SigningMethod

	// Key Pairs for asymmetric tokens (optional)
	JWTKeyPair *KeyPair // For JWT tokens

	// Default token expiration
	DefaultExpiration time.Duration

	// Token refresh configuration
	RefreshConfig *TokenRefreshConfig
}

// TokenManager manages JWT tokens
type TokenManager struct {
	config *TokenManagerConfig
}

// TokenResult represents the result of token creation
type TokenResult struct {
	Token        string    `json:"token"`         // The access token
	RefreshToken string    `json:"refresh_token"` // The refresh token
	Type         TokenType `json:"type"`          // Token type (jwt)
	ExpiresAt    time.Time `json:"expires_at"`    // When the access token expires
	IssuedAt     time.Time `json:"issued_at"`     // When the token was issued
}

// KeyVersion represents a versioned key with metadata
type KeyVersion struct {
	ID         string        `json:"id"`          // Unique key identifier
	Key        []byte        `json:"key"`         // The actual key material
	KeyPair    *KeyPair      `json:"key_pair"`    // For asymmetric keys
	Method     SigningMethod `json:"method"`      // Signing method (HS256, RS256, etc.)
	CreatedAt  time.Time     `json:"created_at"`  // When the key was created
	ExpiresAt  time.Time     `json:"expires_at"`  // When the key expires
	IsActive   bool          `json:"is_active"`   // Whether this is the current active key
	TokenCount int           `json:"token_count"` // Number of tokens using this key
}

// KeyRotationConfig represents configuration for key rotation
type KeyRotationConfig struct {
	KeyDirectory     string        `json:"key_directory"`     // Directory to store keys
	RotationInterval time.Duration `json:"rotation_interval"` // How often to rotate keys
	KeyLifetime      time.Duration `json:"key_lifetime"`      // How long keys are valid
	CleanupInterval  time.Duration `json:"cleanup_interval"`  // How often to clean up old keys
	MaxKeyVersions   int           `json:"max_key_versions"`  // Maximum number of key versions to keep
}

// KeyManager handles key rotation and persistence
type KeyManager struct {
	config        KeyRotationConfig
	keys          map[string]*KeyVersion // key ID -> KeyVersion
	currentKeyID  string                 // ID of the current active key
	mutex         sync.RWMutex
	stopChan      chan struct{}
	cleanupTicker *time.Ticker
}

// NewTokenManager creates a new TokenManager with the given configuration
func NewTokenManager(config *TokenManagerConfig) *TokenManager {
	// Set defaults
	if config.DefaultExpiration == 0 {
		config.DefaultExpiration = 24 * time.Hour
	}
	if config.JWTMethod == "" {
		config.JWTMethod = SigningMethodHS256
	}

	// Note: Refresh config is optional - only set if explicitly provided

	return &TokenManager{
		config: config,
	}
}

// TokenManagerBuilder provides a fluent interface for building TokenManager
type TokenManagerBuilder struct {
	config *TokenManagerConfig
}

// NewTokenManagerBuilder creates a new TokenManagerBuilder
func NewTokenManagerBuilder() *TokenManagerBuilder {
	return &TokenManagerBuilder{
		config: &TokenManagerConfig{
			DefaultExpiration: 24 * time.Hour,
			JWTMethod:         SigningMethodHS256,
		},
	}
}

// WithJWTSecret sets the JWT secret key
func (b *TokenManagerBuilder) WithJWTSecret(secret []byte) *TokenManagerBuilder {
	b.config.JWTSecretKey = secret
	return b
}

// WithJWTMethod sets the JWT signing method
func (b *TokenManagerBuilder) WithJWTMethod(method SigningMethod) *TokenManagerBuilder {
	b.config.JWTMethod = method
	return b
}

// WithJWTKeyPair sets the JWT key pair
func (b *TokenManagerBuilder) WithJWTKeyPair(keyPair *KeyPair) *TokenManagerBuilder {
	b.config.JWTKeyPair = keyPair
	return b
}

// WithDefaultExpiration sets the default token expiration
func (b *TokenManagerBuilder) WithDefaultExpiration(duration time.Duration) *TokenManagerBuilder {
	b.config.DefaultExpiration = duration
	return b
}

// WithRefreshConfig sets the token refresh configuration
func (b *TokenManagerBuilder) WithRefreshConfig(config *TokenRefreshConfig) *TokenManagerBuilder {
	b.config.RefreshConfig = config
	return b
}

// Build creates the TokenManager with the configured settings
func (b *TokenManagerBuilder) Build() *TokenManager {
	return NewTokenManager(b.config)
}

// TokenBuilder provides a fluent interface for building tokens
type TokenBuilder struct {
	tm  *TokenManager
	req TokenRequest
}

// NewToken creates a new TokenBuilder with the given TokenManager
func (tm *TokenManager) NewToken() *TokenBuilder {
	return &TokenBuilder{
		tm: tm,
		req: TokenRequest{
			CustomClaims: make(map[string]interface{}),
		},
	}
}

// WithIssuer sets the token issuer
func (tb *TokenBuilder) WithIssuer(issuer string) *TokenBuilder {
	tb.req.Issuer = issuer
	return tb
}

// WithSubject sets the token subject
func (tb *TokenBuilder) WithSubject(subject string) *TokenBuilder {
	tb.req.Subject = subject
	return tb
}

// WithAudience sets the token audience
func (tb *TokenBuilder) WithAudience(audience string) *TokenBuilder {
	tb.req.Audience = audience
	return tb
}

// WithExpiration sets the token expiration time
func (tb *TokenBuilder) WithExpiration(expiresAt time.Time) *TokenBuilder {
	tb.req.ExpiresAt = expiresAt
	return tb
}

// WithExpirationDuration sets the token expiration as a duration from now
func (tb *TokenBuilder) WithExpirationDuration(duration time.Duration) *TokenBuilder {
	tb.req.ExpiresAt = time.Now().Add(duration)
	return tb
}

// WithNotBefore sets the token not before time
func (tb *TokenBuilder) WithNotBefore(notBefore time.Time) *TokenBuilder {
	tb.req.NotBefore = notBefore
	return tb
}

// WithIssuedAt sets the token issued at time
func (tb *TokenBuilder) WithIssuedAt(issuedAt time.Time) *TokenBuilder {
	tb.req.IssuedAt = issuedAt
	return tb
}

// WithSessionID sets the session ID for the token
func (tb *TokenBuilder) WithSessionID(sessionID string) *TokenBuilder {
	tb.req.SessionID = sessionID
	return tb
}

// WithProviderID sets the provider ID for the token
func (tb *TokenBuilder) WithProviderID(providerID string) *TokenBuilder {
	tb.req.ProviderID = providerID
	return tb
}

// WithClaim adds a custom claim to the token
func (tb *TokenBuilder) WithClaim(key string, value interface{}) *TokenBuilder {
	if tb.req.CustomClaims == nil {
		tb.req.CustomClaims = make(map[string]interface{})
	}
	tb.req.CustomClaims[key] = value
	return tb
}

// WithClaims adds multiple custom claims to the token
func (tb *TokenBuilder) WithClaims(claims map[string]interface{}) *TokenBuilder {
	if tb.req.CustomClaims == nil {
		tb.req.CustomClaims = make(map[string]interface{})
	}
	for key, value := range claims {
		tb.req.CustomClaims[key] = value
	}
	return tb
}

// CreateJWTWithHMAC creates a JWT token using HMAC
func (tb *TokenBuilder) CreateJWTWithHMAC(method SigningMethod) (*TokenResult, error) {
	// Set default expiration if not provided
	if tb.req.ExpiresAt.IsZero() {
		tb.req.ExpiresAt = time.Now().Add(tb.tm.config.DefaultExpiration)
	}

	// Generate session_id if not provided in SessionID field or custom claims
	if tb.req.SessionID == "" {
		// Check if session_id is provided in custom claims
		if sessionIDClaim, exists := tb.req.CustomClaims["session_id"]; exists {
			if sessionIDStr, ok := sessionIDClaim.(string); ok && sessionIDStr != "" {
				tb.req.SessionID = sessionIDStr
			} else {
				tb.req.SessionID = generateSessionID()
			}
		} else {
			tb.req.SessionID = generateSessionID()
		}
	}

	// Remove session_id from custom claims since it's now in the SessionID field
	delete(tb.req.CustomClaims, "session_id")

	// Extract provider_id from custom claims if provided
	if tb.req.ProviderID == "" {
		if providerIDClaim, exists := tb.req.CustomClaims["provider_id"]; exists {
			if providerIDStr, ok := providerIDClaim.(string); ok && providerIDStr != "" {
				tb.req.ProviderID = providerIDStr
			}
		}
	}

	// Remove provider_id from custom claims since it's now in the ProviderID field
	delete(tb.req.CustomClaims, "provider_id")

	tokenString, err := CreateJwtTokenWithMethod(tb.req, tb.tm.config.JWTSecretKey, method)
	if err != nil {
		return nil, fmt.Errorf("failed to create HMAC JWT token: %w", err)
	}

	// Generate embedded refresh token if refresh config is available
	var refreshToken string
	if tb.tm.config.RefreshConfig != nil {
		refreshToken, err = tb.tm.generateEmbeddedRefreshJWT(tb.req, tokenString, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to generate embedded refresh token: %w", err)
		}
	}

	return &TokenResult{
		Token:        tokenString,
		RefreshToken: refreshToken,
		Type:         TokenTypeJWT,
		ExpiresAt:    tb.req.ExpiresAt,
		IssuedAt:     tb.req.IssuedAt,
	}, nil
}

// CreateJWTWithKeyPair creates a JWT token using a specific key pair
func (tb *TokenBuilder) CreateJWTWithKeyPair(keyPair KeyPair) (*TokenResult, error) {
	// Set default expiration if not provided
	if tb.req.ExpiresAt.IsZero() {
		tb.req.ExpiresAt = time.Now().Add(tb.tm.config.DefaultExpiration)
	}

	// Generate session_id if not provided in SessionID field or custom claims
	if tb.req.SessionID == "" {
		// Check if session_id is provided in custom claims
		if sessionIDClaim, exists := tb.req.CustomClaims["session_id"]; exists {
			if sessionIDStr, ok := sessionIDClaim.(string); ok && sessionIDStr != "" {
				tb.req.SessionID = sessionIDStr
			} else {
				tb.req.SessionID = generateSessionID()
			}
		} else {
			tb.req.SessionID = generateSessionID()
		}
	}

	// Remove session_id from custom claims since it's now in the SessionID field
	delete(tb.req.CustomClaims, "session_id")

	// Extract provider_id from custom claims if provided
	if tb.req.ProviderID == "" {
		if providerIDClaim, exists := tb.req.CustomClaims["provider_id"]; exists {
			if providerIDStr, ok := providerIDClaim.(string); ok && providerIDStr != "" {
				tb.req.ProviderID = providerIDStr
			}
		}
	}

	// Remove provider_id from custom claims since it's now in the ProviderID field
	delete(tb.req.CustomClaims, "provider_id")

	tokenString, err := CreateJwtTokenWithKeyPair(tb.req, keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWT token with key pair: %w", err)
	}

	// Generate embedded refresh token if refresh config is available
	var refreshToken string
	if tb.tm.config.RefreshConfig != nil {
		refreshToken, err = tb.tm.generateEmbeddedRefreshJWTWithKeyPair(tb.req, tokenString, keyPair, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to generate embedded refresh token: %w", err)
		}
	}

	return &TokenResult{
		Token:        tokenString,
		RefreshToken: refreshToken,
		Type:         TokenTypeJWT,
		ExpiresAt:    tb.req.ExpiresAt,
		IssuedAt:     tb.req.IssuedAt,
	}, nil
}

// CreateJWTToken creates a JWT token using the TokenManager configuration
func (tm *TokenManager) CreateJWTToken(req TokenRequest) (*TokenResult, error) {
	// Set default expiration if not provided
	if req.ExpiresAt.IsZero() {
		req.ExpiresAt = time.Now().Add(tm.config.DefaultExpiration)
	}

	var tokenString string
	var err error

	if tm.config.JWTKeyPair != nil {
		// Use asymmetric key pair
		tokenString, err = CreateJwtTokenWithKeyPair(req, *tm.config.JWTKeyPair)
	} else {
		// Use HMAC with secret key
		tokenString, err = CreateJwtTokenWithMethod(req, tm.config.JWTSecretKey, tm.config.JWTMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create JWT token: %w", err)
	}

	return &TokenResult{
		Token:     tokenString,
		Type:      TokenTypeJWT,
		ExpiresAt: req.ExpiresAt,
		IssuedAt:  req.IssuedAt,
	}, nil
}

// ValidateToken validates a JWT token
func (tm *TokenManager) ValidateToken(token string) (*TokenRequest, error) {
	return tm.validateJWTToken(token)
}

// ValidateJWTWithHMAC validates a JWT token using HMAC
func (tm *TokenManager) ValidateJWTWithHMAC(token string, method SigningMethod) (*TokenRequest, error) {
	parsedToken, err := ParseJwtTokenWithMethod(token, tm.config.JWTSecretKey, method)
	if err != nil {
		return nil, fmt.Errorf("failed to parse HMAC JWT token: %w", err)
	}

	// Validate token claims
	if err := ValidateTokenClaims(parsedToken); err != nil {
		return nil, fmt.Errorf("JWT token validation failed: %w", err)
	}

	// Extract claims and convert to TokenRequest
	claims := parsedToken.Claims.(jwt.MapClaims)

	tokenReq := &TokenRequest{
		Issuer:       getStringClaim(claims, "iss"),
		Subject:      getStringClaim(claims, "sub"),
		Audience:     getStringClaim(claims, "aud"),
		ExpiresAt:    getTimeClaim(claims, "exp"),
		NotBefore:    getTimeClaim(claims, "nbf"),
		IssuedAt:     getTimeClaim(claims, "iat"),
		SessionID:    getStringClaim(claims, "session_id"),
		ProviderID:   getStringClaim(claims, "provider_id"),
		CustomClaims: make(map[string]interface{}),
	}

	// Add custom claims (exclude standard claims)
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
		"session_id": true, "provider_id": true,
	}

	for key, value := range claims {
		if !standardClaims[key] {
			tokenReq.CustomClaims[key] = value
		}
	}

	return tokenReq, nil
}

// ValidateJWTWithKeyPair validates a JWT token using a specific key pair
func (tm *TokenManager) ValidateJWTWithKeyPair(token string, keyPair KeyPair) (*TokenRequest, error) {
	parsedToken, err := ParseJwtTokenWithKeyPair(token, keyPair)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token with key pair: %w", err)
	}

	// Validate token claims
	if err := ValidateTokenClaims(parsedToken); err != nil {
		return nil, fmt.Errorf("JWT token validation failed: %w", err)
	}

	// Extract claims and convert to TokenRequest
	claims := parsedToken.Claims.(jwt.MapClaims)

	tokenReq := &TokenRequest{
		Issuer:       getStringClaim(claims, "iss"),
		Subject:      getStringClaim(claims, "sub"),
		Audience:     getStringClaim(claims, "aud"),
		ExpiresAt:    getTimeClaim(claims, "exp"),
		NotBefore:    getTimeClaim(claims, "nbf"),
		IssuedAt:     getTimeClaim(claims, "iat"),
		SessionID:    getStringClaim(claims, "session_id"),
		ProviderID:   getStringClaim(claims, "provider_id"),
		CustomClaims: make(map[string]interface{}),
	}

	// Add custom claims (exclude standard claims)
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
		"session_id": true, "provider_id": true,
	}

	for key, value := range claims {
		if !standardClaims[key] {
			tokenReq.CustomClaims[key] = value
		}
	}

	return tokenReq, nil
}

// ValidateJWTToken validates a JWT token
func (tm *TokenManager) ValidateJWTToken(token string) (*TokenRequest, error) {
	return tm.validateJWTToken(token)
}

// detectTokenType detects whether a token is JWT
func (tm *TokenManager) detectTokenType(token string) TokenType {
	// JWT tokens have 3 parts separated by dots
	parts := splitToken(token, ".")
	if len(parts) == 3 {
		// Additional check: try to decode the header
		if _, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
			return TokenTypeJWT
		}
	}

	return ""
}

// validateJWTToken validates a JWT token and returns the TokenRequest
func (tm *TokenManager) validateJWTToken(token string) (*TokenRequest, error) {
	var parsedToken *jwt.Token
	var err error

	if tm.config.JWTKeyPair != nil {
		// Use asymmetric key pair
		parsedToken, err = ParseJwtTokenWithKeyPair(token, *tm.config.JWTKeyPair)
	} else {
		// Use HMAC with secret key
		parsedToken, err = ParseJwtTokenWithMethod(token, tm.config.JWTSecretKey, tm.config.JWTMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT token: %w", err)
	}

	// Validate token claims
	if err := ValidateTokenClaims(parsedToken); err != nil {
		return nil, fmt.Errorf("JWT token validation failed: %w", err)
	}

	// Extract claims and convert to TokenRequest
	claims := parsedToken.Claims.(jwt.MapClaims)

	tokenReq := &TokenRequest{
		Issuer:       getStringClaim(claims, "iss"),
		Subject:      getStringClaim(claims, "sub"),
		Audience:     getStringClaim(claims, "aud"),
		ExpiresAt:    getTimeClaim(claims, "exp"),
		NotBefore:    getTimeClaim(claims, "nbf"),
		IssuedAt:     getTimeClaim(claims, "iat"),
		SessionID:    getStringClaim(claims, "session_id"),
		ProviderID:   getStringClaim(claims, "provider_id"),
		CustomClaims: make(map[string]interface{}),
	}

	// Add custom claims (exclude standard claims)
	standardClaims := map[string]bool{
		"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true,
		"session_id": true, "provider_id": true,
	}

	for key, value := range claims {
		if !standardClaims[key] {
			tokenReq.CustomClaims[key] = value
		}
	}

	return tokenReq, nil
}

// createHMACSignatureWithMethod creates a signature using HMAC with specified secret key and method
func (tm *TokenManager) createHMACSignatureWithMethod(data []byte, secretKey []byte, method SigningMethod) (string, error) {
	// Create HMAC signature based on the method
	var h hash.Hash
	switch method {
	case SigningMethodHS256:
		h = hmac.New(sha256.New, secretKey)
	case SigningMethodHS384:
		h = hmac.New(sha512.New384, secretKey)
	case SigningMethodHS512:
		h = hmac.New(sha512.New, secretKey)
	default:
		return "", fmt.Errorf("unsupported HMAC method: %s", method)
	}

	h.Write(data)
	signature := h.Sum(nil)
	return base64.URLEncoding.EncodeToString(signature), nil
}

// createKeyPairSignature creates a signature using a specific key pair
func (tm *TokenManager) createKeyPairSignature(data []byte, keyPair KeyPair) (string, error) {
	// Hash the data
	hasher := sha256.New()
	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	// Sign based on key type
	switch key := keyPair.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashedData)
		if err != nil {
			return "", fmt.Errorf("failed to sign with RSA: %w", err)
		}
		return base64.URLEncoding.EncodeToString(signature), nil

	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hashedData)
		if err != nil {
			return "", fmt.Errorf("failed to sign with ECDSA: %w", err)
		}
		// Encode r and s as DER
		signature := append(r.Bytes(), s.Bytes()...)
		return base64.URLEncoding.EncodeToString(signature), nil

	case ed25519.PrivateKey:
		signature := ed25519.Sign(key, hashedData)
		return base64.URLEncoding.EncodeToString(signature), nil

	default:
		return "", fmt.Errorf("unsupported private key type for token signing")
	}
}

// verifyHMACSignatureWithMethod verifies a signature using HMAC with specified secret key and method
func (tm *TokenManager) verifyHMACSignatureWithMethod(data []byte, signature string, secretKey []byte, method SigningMethod) bool {
	// Create expected signature using the same method as createHMACSignature
	expectedSig, err := tm.createHMACSignatureWithMethod(data, secretKey, method)
	if err != nil {
		return false
	}

	// Compare signatures
	return signature == expectedSig
}

// verifyKeyPairSignature verifies a signature using a specific key pair
func (tm *TokenManager) verifyKeyPairSignature(data []byte, signature string, keyPair KeyPair) bool {
	// Decode the signature
	decodedSig, err := base64.URLEncoding.DecodeString(signature)
	if err != nil {
		return false
	}

	// Hash the data
	hasher := sha256.New()
	hasher.Write(data)
	hashedData := hasher.Sum(nil)

	// Verify based on key type
	switch key := keyPair.PublicKey.(type) {
	case *rsa.PublicKey:
		err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hashedData, decodedSig)
		return err == nil

	case *ecdsa.PublicKey:
		// For ECDSA, we need to split the signature back into r and s
		if len(decodedSig) != 64 { // 32 bytes for r + 32 bytes for s
			return false
		}
		r := new(big.Int).SetBytes(decodedSig[:32])
		s := new(big.Int).SetBytes(decodedSig[32:])
		return ecdsa.Verify(key, hashedData, r, s)

	case ed25519.PublicKey:
		return ed25519.Verify(key, hashedData, decodedSig)

	default:
		return false
	}
}

// Helper functions
func splitToken(token, sep string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(token); i++ {
		if token[i:i+len(sep)] == sep {
			parts = append(parts, token[start:i])
			start = i + len(sep)
		}
	}
	if start < len(token) {
		parts = append(parts, token[start:])
	}
	return parts
}

func getStringClaim(claims jwt.MapClaims, key string) string {
	if val, ok := claims[key].(string); ok {
		return val
	}
	return ""
}

func getTimeClaim(claims jwt.MapClaims, key string) time.Time {
	if val, ok := claims[key].(float64); ok {
		return time.Unix(int64(val), 0)
	}
	return time.Time{}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// NewKeyManager creates a new KeyManager with the given configuration
func NewKeyManager(config KeyRotationConfig) (*KeyManager, error) {
	// Set default values
	if config.KeyDirectory == "" {
		config.KeyDirectory = "./keys"
	}
	if config.RotationInterval == 0 {
		config.RotationInterval = 24 * time.Hour
	}
	if config.KeyLifetime == 0 {
		config.KeyLifetime = 7 * 24 * time.Hour // 7 days
	}
	if config.CleanupInterval == 0 {
		config.CleanupInterval = 1 * time.Hour
	}
	if config.MaxKeyVersions == 0 {
		config.MaxKeyVersions = 10
	}

	km := &KeyManager{
		config:   config,
		keys:     make(map[string]*KeyVersion),
		stopChan: make(chan struct{}),
	}

	// Create key directory if it doesn't exist
	if err := os.MkdirAll(config.KeyDirectory, 0700); err != nil {
		return nil, fmt.Errorf("failed to create key directory: %w", err)
	}

	// Load existing keys
	if err := km.loadKeys(); err != nil {
		return nil, fmt.Errorf("failed to load keys: %w", err)
	}

	// Start cleanup routine
	km.startCleanupRoutine()

	return km, nil
}

// GenerateNewKey creates a new key version
func (km *KeyManager) GenerateNewKey(method SigningMethod) (*KeyVersion, error) {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	keyID := fmt.Sprintf("key_%d", time.Now().UnixNano())
	now := time.Now()

	var keyVersion *KeyVersion

	switch method {
	case SigningMethodHS256, SigningMethodHS384, SigningMethodHS512:
		// Generate HMAC key
		key := make([]byte, 32) // 256 bits
		if _, err := rand.Read(key); err != nil {
			return nil, fmt.Errorf("failed to generate HMAC key: %w", err)
		}

		keyVersion = &KeyVersion{
			ID:        keyID,
			Key:       key,
			Method:    method,
			CreatedAt: now,
			ExpiresAt: now.Add(km.config.KeyLifetime),
			IsActive:  true,
		}

	case SigningMethodRS256, SigningMethodRS384, SigningMethodRS512:
		// Generate RSA key pair
		keyPair, err := GenerateRSAKeyPair(2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
		}

		keyVersion = &KeyVersion{
			ID:        keyID,
			KeyPair:   keyPair,
			Method:    method,
			CreatedAt: now,
			ExpiresAt: now.Add(km.config.KeyLifetime),
			IsActive:  true,
		}

	case SigningMethodES256, SigningMethodES384, SigningMethodES512:
		// Generate ECDSA key pair
		keyPair, err := GenerateECDSAKeyPair(elliptic.P256())
		if err != nil {
			return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
		}

		keyVersion = &KeyVersion{
			ID:        keyID,
			KeyPair:   keyPair,
			Method:    method,
			CreatedAt: now,
			ExpiresAt: now.Add(km.config.KeyLifetime),
			IsActive:  true,
		}

	case SigningMethodEdDSA:
		// Generate EdDSA key pair
		keyPair, err := GenerateEdDSAKeyPair()
		if err != nil {
			return nil, fmt.Errorf("failed to generate EdDSA key pair: %w", err)
		}

		keyVersion = &KeyVersion{
			ID:        keyID,
			KeyPair:   keyPair,
			Method:    method,
			CreatedAt: now,
			ExpiresAt: now.Add(km.config.KeyLifetime),
			IsActive:  true,
		}

	default:
		return nil, fmt.Errorf("unsupported signing method: %s", method)
	}

	// Deactivate previous active key
	if km.currentKeyID != "" {
		if oldKey, exists := km.keys[km.currentKeyID]; exists {
			oldKey.IsActive = false
		}
	}

	// Add new key
	km.keys[keyID] = keyVersion
	km.currentKeyID = keyID

	// Persist the key
	if err := km.saveKey(keyVersion); err != nil {
		return nil, fmt.Errorf("failed to save key: %w", err)
	}

	return keyVersion, nil
}

// GetCurrentKey returns the current active key
func (km *KeyManager) GetCurrentKey() (*KeyVersion, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	if km.currentKeyID == "" {
		return nil, fmt.Errorf("no active key found")
	}

	key, exists := km.keys[km.currentKeyID]
	if !exists {
		return nil, fmt.Errorf("current key not found")
	}

	return key, nil
}

// GetKeyByID returns a key by its ID
func (km *KeyManager) GetKeyByID(keyID string) (*KeyVersion, error) {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	key, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	return key, nil
}

// IncrementTokenCount increments the token count for a key
func (km *KeyManager) IncrementTokenCount(keyID string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	key, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	key.TokenCount++
	return km.saveKey(key)
}

// DecrementTokenCount decrements the token count for a key
func (km *KeyManager) DecrementTokenCount(keyID string) error {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	key, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	if key.TokenCount > 0 {
		key.TokenCount--
	}
	return km.saveKey(key)
}

// loadKeys loads all keys from the key directory
func (km *KeyManager) loadKeys() error {
	files, err := ioutil.ReadDir(km.config.KeyDirectory)
	if err != nil {
		return fmt.Errorf("failed to read key directory: %w", err)
	}

	for _, file := range files {
		if filepath.Ext(file.Name()) == ".json" {
			keyID := file.Name()[:len(file.Name())-5] // Remove .json extension

			keyPath := filepath.Join(km.config.KeyDirectory, file.Name())
			data, err := ioutil.ReadFile(keyPath)
			if err != nil {
				continue // Skip corrupted files
			}

			var keyVersion KeyVersion
			if err := json.Unmarshal(data, &keyVersion); err != nil {
				continue // Skip corrupted files
			}

			km.keys[keyID] = &keyVersion
			if keyVersion.IsActive {
				km.currentKeyID = keyID
			}
		}
	}

	return nil
}

// saveKey saves a key to disk
func (km *KeyManager) saveKey(key *KeyVersion) error {
	keyPath := filepath.Join(km.config.KeyDirectory, key.ID+".json")

	data, err := json.MarshalIndent(key, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	return ioutil.WriteFile(keyPath, data, 0600)
}

// startCleanupRoutine starts the background cleanup routine
func (km *KeyManager) startCleanupRoutine() {
	km.cleanupTicker = time.NewTicker(km.config.CleanupInterval)

	go func() {
		for {
			select {
			case <-km.cleanupTicker.C:
				km.cleanupExpiredKeys()
			case <-km.stopChan:
				km.cleanupTicker.Stop()
				return
			}
		}
	}()
}

// cleanupExpiredKeys removes keys that have expired and have no active tokens
func (km *KeyManager) cleanupExpiredKeys() {
	km.mutex.Lock()
	defer km.mutex.Unlock()

	now := time.Now()
	var keysToDelete []string

	for keyID, key := range km.keys {
		// Skip if key is still active
		if key.IsActive {
			continue
		}

		// Skip if key hasn't expired yet
		if key.ExpiresAt.After(now) {
			continue
		}

		// Skip if key still has active tokens
		if key.TokenCount > 0 {
			continue
		}

		keysToDelete = append(keysToDelete, keyID)
	}

	// Delete expired keys
	for _, keyID := range keysToDelete {
		keyPath := filepath.Join(km.config.KeyDirectory, keyID+".json")
		os.Remove(keyPath)
		delete(km.keys, keyID)
	}

	// If we deleted the current key, find a new one
	if km.currentKeyID != "" {
		if _, exists := km.keys[km.currentKeyID]; !exists {
			km.currentKeyID = ""
			// Find the most recent active key
			var latestKey *KeyVersion
			for _, key := range km.keys {
				if key.IsActive && (latestKey == nil || key.CreatedAt.After(latestKey.CreatedAt)) {
					latestKey = key
				}
			}
			if latestKey != nil {
				km.currentKeyID = latestKey.ID
			}
		}
	}
}

// Stop stops the key manager and its background routines
func (km *KeyManager) Stop() {
	close(km.stopChan)
	if km.cleanupTicker != nil {
		km.cleanupTicker.Stop()
	}
}

// RotateKey generates a new key and makes it active
func (km *KeyManager) RotateKey(method SigningMethod) (*KeyVersion, error) {
	return km.GenerateNewKey(method)
}

// GetKeyVersions returns all key versions
func (km *KeyManager) GetKeyVersions() []*KeyVersion {
	km.mutex.RLock()
	defer km.mutex.RUnlock()

	versions := make([]*KeyVersion, 0, len(km.keys))
	for _, key := range km.keys {
		versions = append(versions, key)
	}

	return versions
}

// ============================================================================
// Helper Functions
// ============================================================================

// generateSessionID generates a unique session ID
func generateSessionID() string {
	return GenerateSessionID()
}

// DetectTokenType detects the type of token (JWT)
func DetectTokenType(token string) TokenType {
	// JWT tokens have 3 parts separated by dots
	parts := splitToken(token, ".")
	if len(parts) == 3 {
		return TokenTypeJWT
	}
	return ""
}

// ============================================================================
// Embedded Refresh Token Methods
// ============================================================================

// generateEmbeddedRefreshJWT creates a JWT refresh token embedded with access token info
func (tm *TokenManager) generateEmbeddedRefreshJWT(originalReq TokenRequest, accessToken string, attempts int) (string, error) {
	if tm.config.RefreshConfig == nil {
		return "", fmt.Errorf("refresh configuration not set")
	}

	// Create refresh token with longer expiration
	refreshReq := TokenRequest{
		Issuer:     originalReq.Issuer,
		Subject:    originalReq.Subject,
		Audience:   originalReq.Audience,
		ExpiresAt:  time.Now().Add(tm.config.RefreshConfig.RefreshTokenExpiry),
		NotBefore:  time.Now(),
		IssuedAt:   time.Now(),
		SessionID:  originalReq.SessionID,  // Preserve session_id from original token
		ProviderID: originalReq.ProviderID, // Preserve provider_id from original token
		CustomClaims: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "refresh",
			"attempts":     attempts,
		},
	}

	// Copy original custom claims
	if originalReq.CustomClaims != nil {
		for k, v := range originalReq.CustomClaims {
			refreshReq.CustomClaims[k] = v
		}
	}

	// Create JWT refresh token
	refreshToken, err := CreateJwtTokenWithMethod(refreshReq, tm.config.JWTSecretKey, tm.config.JWTMethod)
	if err != nil {
		return "", fmt.Errorf("failed to create refresh JWT: %w", err)
	}

	return refreshToken, nil
}

// generateEmbeddedRefreshJWTWithKeyPair creates a JWT refresh token with key pair
func (tm *TokenManager) generateEmbeddedRefreshJWTWithKeyPair(originalReq TokenRequest, accessToken string, keyPair KeyPair, attempts int) (string, error) {
	if tm.config.RefreshConfig == nil {
		return "", fmt.Errorf("refresh configuration not set")
	}

	// Create refresh token with longer expiration
	refreshReq := TokenRequest{
		Issuer:     originalReq.Issuer,
		Subject:    originalReq.Subject,
		Audience:   originalReq.Audience,
		ExpiresAt:  time.Now().Add(tm.config.RefreshConfig.RefreshTokenExpiry),
		NotBefore:  time.Now(),
		IssuedAt:   time.Now(),
		SessionID:  originalReq.SessionID,  // Preserve session_id from original token
		ProviderID: originalReq.ProviderID, // Preserve provider_id from original token
		CustomClaims: map[string]interface{}{
			"access_token": accessToken,
			"token_type":   "refresh",
			"attempts":     attempts,
		},
	}

	// Copy original custom claims
	if originalReq.CustomClaims != nil {
		for k, v := range originalReq.CustomClaims {
			refreshReq.CustomClaims[k] = v
		}
	}

	// Create JWT refresh token with key pair
	refreshToken, err := CreateJwtTokenWithKeyPair(refreshReq, keyPair)
	if err != nil {
		return "", fmt.Errorf("failed to create refresh JWT with key pair: %w", err)
	}

	return refreshToken, nil
}

// RefreshToken refreshes an access token using an embedded refresh token
func (tm *TokenManager) RefreshToken(refreshToken string) (*TokenResult, error) {
	if tm.config.RefreshConfig == nil {
		return nil, fmt.Errorf("refresh configuration not set")
	}

	// Parse the refresh token to get its claims
	tokenType := DetectTokenType(refreshToken)
	if tokenType != TokenTypeJWT {
		return nil, fmt.Errorf("only JWT refresh tokens are supported")
	}

	var refreshClaims *TokenRequest
	var err error

	if tm.config.JWTKeyPair != nil {
		refreshClaims, err = tm.ValidateJWTWithKeyPair(refreshToken, *tm.config.JWTKeyPair)
	} else {
		refreshClaims, err = tm.ValidateJWTWithHMAC(refreshToken, tm.config.JWTMethod)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse refresh token: %w", err)
	}

	// Check if it's actually a refresh token
	if tokenType, ok := refreshClaims.CustomClaims["token_type"]; !ok || tokenType != "refresh" {
		return nil, fmt.Errorf("invalid refresh token")
	}

	// Check attempts (JSON unmarshaling converts numbers to float64)
	attempts := 0
	if attemptsFloat, ok := refreshClaims.CustomClaims["attempts"].(float64); ok {
		attempts = int(attemptsFloat)
	}

	// Check attempts limit
	if tm.config.RefreshConfig.MaxRefreshAttempts < 0 {
		// Negative values mean 0 attempts allowed
		return nil, fmt.Errorf("max refresh attempts exceeded")
	} else if tm.config.RefreshConfig.MaxRefreshAttempts == 0 {
		// 0 means no limit
		// Allow unlimited attempts
	} else if attempts >= tm.config.RefreshConfig.MaxRefreshAttempts {
		return nil, fmt.Errorf("max refresh attempts exceeded")
	}

	// Get the original access token from the refresh token
	accessToken, ok := refreshClaims.CustomClaims["access_token"].(string)
	if !ok {
		return nil, fmt.Errorf("invalid refresh token: missing access token")
	}

	// Parse the original access token to get its claims
	originalClaims, err := tm.parseAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to parse original access token: %w", err)
	}

	// Create new access token with same claims but new expiration
	now := time.Now()
	newTokenReq := TokenRequest{
		Issuer:       originalClaims.Issuer,
		Subject:      originalClaims.Subject,
		Audience:     originalClaims.Audience,
		ExpiresAt:    now.Add(tm.config.DefaultExpiration),
		NotBefore:    now,
		IssuedAt:     now,
		SessionID:    originalClaims.SessionID,  // Preserve session_id from original token
		ProviderID:   originalClaims.ProviderID, // Preserve provider_id from original token
		CustomClaims: originalClaims.CustomClaims,
	}

	// Add refreshed claim
	if newTokenReq.CustomClaims == nil {
		newTokenReq.CustomClaims = make(map[string]interface{})
	}
	newTokenReq.CustomClaims["refreshed"] = true

	// Create new token using the TokenBuilder
	tokenBuilder := tm.NewToken().
		WithIssuer(newTokenReq.Issuer).
		WithSubject(newTokenReq.Subject).
		WithAudience(newTokenReq.Audience).
		WithExpiration(newTokenReq.ExpiresAt).
		WithNotBefore(newTokenReq.NotBefore).
		WithIssuedAt(newTokenReq.IssuedAt)

	// Add custom claims
	for key, value := range newTokenReq.CustomClaims {
		tokenBuilder = tokenBuilder.WithClaim(key, value)
	}

	// Use the configured method for creating the token
	var result *TokenResult
	var createErr error

	if tm.config.JWTKeyPair != nil {
		result, createErr = tokenBuilder.CreateJWTWithKeyPair(*tm.config.JWTKeyPair)
	} else {
		result, createErr = tokenBuilder.CreateJWTWithHMAC(tm.config.JWTMethod)
	}

	if createErr != nil {
		return nil, fmt.Errorf("failed to create refreshed token: %w", createErr)
	}

	// Create new refresh token with incremented attempts counter
	var newRefreshToken string
	if tm.config.JWTKeyPair != nil {
		newRefreshToken, createErr = tm.generateEmbeddedRefreshJWTWithKeyPair(newTokenReq, result.Token, *tm.config.JWTKeyPair, attempts+1)
	} else {
		newRefreshToken, createErr = tm.generateEmbeddedRefreshJWT(newTokenReq, result.Token, attempts+1)
	}

	if createErr != nil {
		return nil, fmt.Errorf("failed to create new refresh token: %w", createErr)
	}

	// Update the result with the new refresh token
	result.RefreshToken = newRefreshToken

	return result, nil
}

// parseAccessToken parses an access token and returns its claims
func (tm *TokenManager) parseAccessToken(accessToken string) (*TokenRequest, error) {
	tokenType := DetectTokenType(accessToken)
	if tokenType != TokenTypeJWT {
		return nil, fmt.Errorf("only JWT tokens are supported")
	}

	if tm.config.JWTKeyPair != nil {
		return tm.ValidateJWTWithKeyPair(accessToken, *tm.config.JWTKeyPair)
	} else {
		return tm.ValidateJWTWithHMAC(accessToken, tm.config.JWTMethod)
	}
}
