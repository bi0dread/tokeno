# Tokeno 🔐

[![Go Version](https://img.shields.io/badge/Go-1.21+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/bi0dread/tokeno)](https://goreportcard.com/report/github.com/bi0dread/tokeno)

A comprehensive Go package for creating and validating JWT tokens with support for multiple signing algorithms, automatic key rotation, and enterprise-grade security features.

## 📋 Table of Contents

- [🚀 Quick Start](#-quick-start)
- [✨ Features](#-features)
- [📦 Installation](#-installation)
- [📚 Usage](#-usage)
  - [Basic TokenManager](#basic-tokenmanager)
  - [JWT Tokens with HMAC](#-jwt-tokens-with-hmac)
  - [JWT Tokens with RSA Key Pairs](#-jwt-tokens-with-rsa-key-pairs)
  - [Key Rotation](#-key-rotation)
  - [Builder Pattern](#️-builder-pattern)
  - [Refresh Tokens](#-refresh-tokens)
  - [Auto-Detection](#-auto-detection)
- [📖 Complete Example](#-complete-example)
- [🔄 Key Rotation](#key-rotation)
- [📊 API Reference](#-api-reference)
- [🧪 Testing](#-testing)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)

## 🚀 Quick Start

```go
package main

import (
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    // Create TokenManager with refresh tokens
    tm := tokeno.NewTokenManagerBuilder().
        WithJWTSecret([]byte("your-secret-key")).
        WithDefaultExpiration(24 * time.Hour).
        WithRefreshConfig(&tokeno.TokenRefreshConfig{
            MaxRefreshAttempts: 5,
            RefreshTokenExpiry: 7 * 24 * time.Hour,
        }).
        Build()

    // Create JWT token with refresh token
    jwtResult, err := tm.NewToken().
        WithIssuer("my-service").
        WithSubject("user123").
        WithClaim("role", "admin").
        CreateJWTWithHMAC(tokeno.SigningMethodHS256)

    if err != nil {
        panic(err)
    }

    fmt.Printf("JWT Token: %s\n", jwtResult.Token)
    fmt.Printf("Refresh Token: %s\n", jwtResult.RefreshToken)

    // Validate token
    validated, err := tm.ValidateJWTToken(jwtResult.Token)
    if err != nil {
        panic(err)
    }

    fmt.Printf("Validated user: %s\n", validated.Subject)

    // Use refresh token to get new access token
    newResult, err := tm.RefreshToken(jwtResult.RefreshToken)
    if err != nil {
        panic(err)
    }

    fmt.Printf("New Access Token: %s\n", newResult.Token)
}
```

## ✨ Features

### 🔑 Token Support
- **JWT Tokens**: Full RFC 7519 compliance with standard claims
- **Refresh Tokens**: Automatic refresh token generation with security controls
- **Auto-Detection**: Automatic token type detection and validation

### 🔐 Security & Signing
- **Multiple Algorithms**: HMAC (HS256/384/512), RSA (RS256/384/512), ECDSA (ES256/384/512), EdDSA
- **Key Generation**: Built-in utilities for generating secure key pairs
- **Key Rotation**: Automatic key rotation with persistence and smart cleanup
- **Token Tracking**: Track active tokens to prevent premature key deletion
- **Refresh Security**: Configurable attempt limits and expiration for refresh tokens

### 🛠️ Developer Experience
- **Builder Pattern**: Fluent configuration API
- **Method Chaining**: Intuitive token creation and validation
- **Type Safety**: Strongly typed APIs with comprehensive error handling
- **Comprehensive Testing**: 50+ tests with full coverage

### 🏢 Enterprise Ready
- **Thread-Safe**: All operations are thread-safe with proper locking
- **Persistence**: Keys are stored on disk and survive restarts
- **Configurable**: Flexible configuration for different environments
- **Production Ready**: Battle-tested with comprehensive error handling

## 📦 Installation

```bash
go get github.com/bi0dread/tokeno
```

## 📚 Usage

### Basic TokenManager

```go
import "github.com/bi0dread/tokeno"

// Create TokenManager with configuration
tm := tokeno.NewTokenManagerBuilder().
    WithJWTSecret([]byte("your-jwt-secret")).
    WithDefaultExpiration(24 * time.Hour).
    Build()

// Create and validate tokens
jwtResult, _ := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)

validated, _ := tm.ValidateJWTToken(jwtResult.Token)
```

### 🔐 JWT Tokens with HMAC

```go
// Create JWT token with HMAC
jwtResult, err := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    WithAudience("api-clients").
    WithExpirationDuration(1 * time.Hour).
    WithClaim("role", "admin").
    WithClaim("permissions", []string{"read", "write"}).
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)

// Validate JWT token
validated, err := tm.ValidateJWTWithHMAC(jwtResult.Token, tokeno.SigningMethodHS256)
```

### 🔑 JWT Tokens with RSA Key Pairs

```go
// Generate RSA key pair
keyPair, err := tokeno.GenerateRSAKeyPair(2048)
if err != nil {
    panic(err)
}

// Create JWT with RSA
jwtResult, err := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    CreateJWTWithKeyPair(*keyPair)

// Validate JWT with key pair
validated, err := tm.ValidateJWTWithKeyPair(jwtResult.Token, *keyPair)
```

### 🔄 Key Rotation

```go
// Configure key rotation
config := tokeno.KeyRotationConfig{
    KeyDirectory:     "./keys",
    RotationInterval: 24 * time.Hour,
    KeyLifetime:      7 * 24 * time.Hour,
    CleanupInterval:  1 * time.Hour,
    MaxKeyVersions:   10,
}

// Create KeyManager
km, err := tokeno.NewKeyManager(config)
if err != nil {
    panic(err)
}
defer km.Stop()

// Generate and rotate keys
key, err := km.GenerateNewKey(tokeno.SigningMethodHS256)
newKey, err := km.RotateKey(tokeno.SigningMethodHS512)

// Track token usage
km.IncrementTokenCount(key.ID)
km.DecrementTokenCount(key.ID)
```

### 🏗️ Builder Pattern

```go
// Create TokenManager using builder pattern
tm := tokeno.NewTokenManagerBuilder().
    WithJWTSecret([]byte("jwt-secret")).
    WithJWTMethod(tokeno.SigningMethodHS512).
    WithJWTKeyPair(rsaKeyPair).
    WithDefaultExpiration(12 * time.Hour).
    WithRefreshConfig(&tokeno.TokenRefreshConfig{
        RefreshThreshold:   30 * time.Minute,
        MaxRefreshAttempts: 5,
        RefreshTokenExpiry: 7 * 24 * time.Hour,
    }).
    Build()
```

### 🔄 Refresh Tokens

Tokeno supports automatic refresh token generation with configurable attempt limits and security controls.

#### Basic Refresh Token Usage

```go
// Create TokenManager with refresh configuration
config := &tokeno.TokenManagerConfig{
    JWTSecretKey: []byte("your-jwt-secret"),
    JWTMethod:    tokeno.SigningMethodHS256,
    RefreshConfig: &tokeno.TokenRefreshConfig{
        RefreshThreshold:   30 * time.Minute,   // Refresh 30 minutes before expiry
        MaxRefreshAttempts: 5,                  // Allow 5 refresh attempts
        RefreshGracePeriod: 5 * time.Minute,    // 5 minute grace period
        RefreshTokenLength: 64,                 // 64 character refresh tokens
        RefreshTokenExpiry: 7 * 24 * time.Hour, // Refresh tokens valid for 7 days
    },
}

tm := tokeno.NewTokenManager(config)

// Create token with automatic refresh token
result, err := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    WithExpiration(time.Now().Add(1 * time.Hour)).
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)

if err != nil {
    panic(err)
}

fmt.Printf("Access Token: %s\n", result.Token)
fmt.Printf("Refresh Token: %s\n", result.RefreshToken)
```

#### Using Refresh Tokens

```go
// Use refresh token to get new access token
newResult, err := tm.RefreshToken(result.RefreshToken)
if err != nil {
    panic(err)
}

fmt.Printf("New Access Token: %s\n", newResult.Token)
fmt.Printf("New Refresh Token: %s\n", newResult.RefreshToken)
```

#### Refresh Token Configuration

The `TokenRefreshConfig` struct provides comprehensive control over refresh token behavior:

```go
type TokenRefreshConfig struct {
    RefreshThreshold   time.Duration // When to start refreshing (e.g., 1 hour before expiry)
    MaxRefreshAttempts int           // Maximum refresh attempts
    RefreshGracePeriod time.Duration // Grace period for refresh
    RefreshTokenLength int           // Length of refresh token (default: 64)
    RefreshTokenExpiry time.Duration // Refresh token expiration (default: 7 days)
}
```

#### MaxRefreshAttempts Security

The `MaxRefreshAttempts` feature provides security controls for refresh token usage:

```go
// Different MaxRefreshAttempts configurations
configs := []struct {
    name        string
    maxAttempts int
    description string
}{
    {"Unlimited", 0, "No limit on refresh attempts"},
    {"Limited", 5, "Allow 5 refresh attempts"},
    {"Strict", 1, "Allow only 1 refresh attempt"},
    {"Disabled", -1, "No refresh attempts allowed"},
}

for _, cfg := range configs {
    refreshConfig := &tokeno.TokenRefreshConfig{
        MaxRefreshAttempts: cfg.maxAttempts,
        RefreshTokenExpiry: 24 * time.Hour,
    }
    
    tm := tokeno.NewTokenManagerBuilder().
        WithJWTSecret([]byte("secret")).
        WithRefreshConfig(refreshConfig).
        Build()
    
    // Use the TokenManager...
}
```

#### Refresh Token with Builder Pattern

```go
// Create TokenManager with refresh config using builder
tm := tokeno.NewTokenManagerBuilder().
    WithJWTSecret([]byte("your-secret")).
    WithJWTMethod(tokeno.SigningMethodHS256).
    WithRefreshConfig(&tokeno.TokenRefreshConfig{
        RefreshThreshold:   1 * time.Hour,
        MaxRefreshAttempts: 3,
        RefreshTokenExpiry: 24 * time.Hour,
    }).
    Build()

// Create token with refresh token
result, err := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    WithExpiration(time.Now().Add(2 * time.Hour)).
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)
```

#### Refresh Token Security Features

- **Attempt Limiting**: Control how many times a refresh token can be used
- **Automatic Expiration**: Refresh tokens expire independently of access tokens
- **Embedded Access Token**: Refresh tokens contain the original access token for validation
- **Incremental Counter**: Each refresh increments an attempt counter for security tracking
- **Grace Period**: Configurable grace period for refresh operations

#### Refresh Token Examples

```bash
# Run refresh token examples
go run cmd/refresh_config_builder_example/main.go
go run cmd/max_refresh_attempts_example/main.go
go run cmd/embedded_refresh_example/main.go
```

### 🔍 Auto-Detection

```go
// Auto-detect and validate any token type
validated, err := tm.ValidateToken(anyTokenString)
if err != nil {
    panic(err)
}

fmt.Printf("Token type: %s\n", validated.Type)
fmt.Printf("Subject: %s\n", validated.Subject)
```

## 📖 Complete Example

```go
package main

import (
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    // Create TokenManager configuration
    config := &tokeno.TokenManagerConfig{
        JWTSecretKey:      []byte("your-jwt-secret-key-here"),
        DefaultExpiration: 24 * time.Hour,
    }
    
    // Create TokenManager
    tm := tokeno.NewTokenManager(config)
    
    now := time.Now()
    tokenReq := tokeno.TokenRequest{
        Issuer:    "my-service",
        Subject:   "user123",
        Audience:  "api-clients",
        ExpiresAt: now.Add(24 * time.Hour),
        NotBefore: now,
        IssuedAt:  now,
        CustomClaims: map[string]interface{}{
            "role": "admin",
            "user_id": 123,
        },
    }
    
    // Create JWT token
    jwtResult, err := tm.CreateJWTToken(tokenReq)
    if err != nil {
        panic(err)
    }
    fmt.Println("JWT Token:", jwtResult.Token)
    
    // Auto-validate token
    validatedJWT, _ := tm.ValidateToken(jwtResult.Token)
    
    fmt.Printf("JWT Issuer: %s\n", validatedJWT.Issuer)
}
```

### Builder Pattern

The TokenManager supports a fluent builder pattern for easy configuration:

```go
// Create TokenManager using builder pattern
tm := tokeno.NewTokenManagerBuilder().
    WithJWTSecret([]byte("jwt-secret")).
    WithJWTMethod(tokeno.SigningMethodHS512).
    WithJWTKeyPair(rsaKeyPair).
    WithDefaultExpiration(12 * time.Hour).
    Build()
```

### Method Chaining for Token Creation

Create tokens using a fluent method chaining interface:

```go
// Create JWT token with method chaining
jwtResult, err := tm.NewToken().
    WithIssuer("my-service").
    WithSubject("user123").
    WithAudience("api-clients").
    WithExpirationDuration(24 * time.Hour).
    WithClaim("role", "admin").
    WithClaim("permissions", []string{"read", "write"}).
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)

```

### TokenBuilder for Explicit Control

The TokenBuilder provides explicit control over token creation and validation:

#### HMAC Functions using TokenBuilder

```go
// Create JWT token with explicit HMAC using TokenBuilder
jwtResult, err := tm.NewToken().
    WithIssuer("issuer").
    WithSubject("subject").
    WithClaims(claims).
    CreateJWTWithHMAC(tokeno.SigningMethodHS256)

// Validate JWT token with explicit HMAC using TokenManager
validatedJWT, err := tm.ValidateJWTWithHMAC(jwtResult.Token, tokeno.SigningMethodHS256)
```

#### Key Pair Functions using TokenBuilder

```go
// Generate key pair
keyPair, err := tokeno.GenerateRSAKeyPair(2048)

// Create JWT token with explicit key pair using TokenBuilder
jwtResult, err := tm.NewToken().
    WithIssuer("issuer").
    WithSubject("subject").
    WithClaims(claims).
    CreateJWTWithKeyPair(*keyPair)

// Validate JWT token with explicit key pair using TokenManager
validatedJWT, err := tm.ValidateJWTWithKeyPair(jwtResult.Token, *keyPair)
```

### HMAC (Symmetric) Example

```go
package main

import (
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    secretKey := []byte("your-secret-key-here")
    now := time.Now()
    
    tokenReq := tokeno.TokenRequest{
        Issuer:    "my-service",
        Subject:   "user123",
        Audience:  "api-clients",
        ExpiresAt: now.Add(24 * time.Hour),
        NotBefore: now,
        IssuedAt:  now,
        CustomClaims: map[string]interface{}{
            "role": "admin",
            "user_id": 123,
        },
    }
    
    // Create JWT token with HMAC
    tokenString, err := tokeno.CreateJwtToken(tokenReq, secretKey)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("HMAC Token:", tokenString)
}
```

### RSA (Asymmetric) Example

```go
package main

import (
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    // Generate RSA key pair
    keyPair, err := tokeno.GenerateRSAKeyPair(2048)
    if err != nil {
        panic(err)
    }
    
    now := time.Now()
    tokenReq := tokeno.TokenRequest{
        Issuer:    "my-service",
        Subject:   "user123",
        Audience:  "api-clients",
        ExpiresAt: now.Add(24 * time.Hour),
        NotBefore: now,
        IssuedAt:  now,
        CustomClaims: map[string]interface{}{
            "role": "admin",
        },
    }
    
    // Create JWT token with RSA
    tokenString, err := tokeno.CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("RSA Token:", tokenString)
    
    // Parse and validate the token
    parsedToken, err := tokeno.ParseJwtTokenWithKeyPair(tokenString, *keyPair)
    if err != nil {
        panic(err)
    }
    
    if err := tokeno.ValidateTokenClaims(parsedToken); err != nil {
        panic(err)
    }
    
    fmt.Println("Token is valid!")
}
```

### ECDSA (Asymmetric) Example

```go
package main

import (
    "crypto/elliptic"
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    // Generate ECDSA key pair
    keyPair, err := tokeno.GenerateECDSAKeyPair(elliptic.P256())
    if err != nil {
        panic(err)
    }
    
    now := time.Now()
    tokenReq := tokeno.TokenRequest{
        Issuer:    "my-service",
        Subject:   "user123",
        Audience:  "api-clients",
        ExpiresAt: now.Add(24 * time.Hour),
        NotBefore: now,
        IssuedAt:  now,
    }
    
    // Create JWT token with ECDSA
    tokenString, err := tokeno.CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("ECDSA Token:", tokenString)
}
```

### EdDSA (Asymmetric) Example

```go
package main

import (
    "fmt"
    "time"
    "github.com/bi0dread/tokeno"
)

func main() {
    // Generate EdDSA key pair
    keyPair, err := tokeno.GenerateEdDSAKeyPair()
    if err != nil {
        panic(err)
    }
    
    now := time.Now()
    tokenReq := tokeno.TokenRequest{
        Issuer:    "my-service",
        Subject:   "user123",
        Audience:  "api-clients",
        ExpiresAt: now.Add(24 * time.Hour),
        NotBefore: now,
        IssuedAt:  now,
    }
    
    // Create JWT token with EdDSA
    tokenString, err := tokeno.CreateJwtTokenWithKeyPair(tokenReq, *keyPair)
    if err != nil {
        panic(err)
    }
    
    fmt.Println("EdDSA Token:", tokenString)
}
```

### TokenManager Configuration

The `TokenManagerConfig` struct configures the TokenManager:

```go
type TokenManagerConfig struct {
    JWTSecretKey      []byte                // Secret key for HMAC JWT tokens
    JWTKeyPair        *KeyPair              // Optional key pair for asymmetric JWT tokens
    DefaultExpiration time.Duration         // Default token expiration (default: 24h)
    RefreshConfig     *TokenRefreshConfig   // Optional refresh token configuration
}
```

### Token Types

#### TokenRequest Structure

The `TokenRequest` struct contains all the required fields for token creation:

```go
type TokenRequest struct {
    Issuer       string                 `json:"issuer"`        // Token issuer
    Subject      string                 `json:"subject"`       // Token subject
    Audience     string                 `json:"audience"`      // Token audience
    ExpiresAt    time.Time              `json:"expires_at"`    // Token expiration time
    NotBefore    time.Time              `json:"not_before"`    // Token valid from time
    IssuedAt     time.Time              `json:"issued_at"`     // Token issued time
    CustomClaims map[string]interface{} `json:"custom_claims"` // Additional custom claims
}
```

#### TokenResult Structure

The `TokenResult` struct contains the result of token creation:

```go
type TokenResult struct {
    Token        string    `json:"token"`         // The generated access token string
    RefreshToken string    `json:"refresh_token"` // The generated refresh token string (if configured)
    Type         TokenType `json:"type"`          // Token type (jwt)
    ExpiresAt    time.Time `json:"expires_at"`    // Token expiration time
    IssuedAt     time.Time `json:"issued_at"`     // Token issued time
}
```

#### Token Types

```go
type TokenType string

const (
    TokenTypeJWT TokenType = "jwt" // JWT token
)
```

## Key Rotation

The `tokeno` package includes a powerful key rotation system that automatically manages cryptographic keys with persistence and cleanup.

### KeyManager

The `KeyManager` handles automatic key rotation, persistence, and cleanup:

```go
// Configure key rotation
config := tokeno.KeyRotationConfig{
    KeyDirectory:     "./keys",           // Directory to store keys
    RotationInterval: 24 * time.Hour,     // How often to rotate keys
    KeyLifetime:      7 * 24 * time.Hour, // How long keys are valid
    CleanupInterval:  1 * time.Hour,      // How often to clean up old keys
    MaxKeyVersions:   10,                 // Maximum number of key versions to keep
}

// Create KeyManager
km, err := tokeno.NewKeyManager(config)
if err != nil {
    log.Fatal(err)
}
defer km.Stop()

// Generate new key
key, err := km.GenerateNewKey(tokeno.SigningMethodHS256)
if err != nil {
    log.Fatal(err)
}

// Get current active key
currentKey, err := km.GetCurrentKey()
if err != nil {
    log.Fatal(err)
}

// Rotate to new key
newKey, err := km.RotateKey(tokeno.SigningMethodHS512)
if err != nil {
    log.Fatal(err)
}

// Track token usage
km.IncrementTokenCount(key.ID)
km.DecrementTokenCount(key.ID)

// Get all key versions
versions := km.GetKeyVersions()
```

### Key Rotation Features

- **Automatic Rotation**: Keys are automatically rotated based on configured intervals
- **Persistence**: Keys are stored on disk and loaded on startup
- **Token Tracking**: Tracks how many tokens are using each key
- **Smart Cleanup**: Only removes keys that have expired AND have no active tokens
- **Multiple Algorithms**: Supports HMAC, RSA, ECDSA, and EdDSA key rotation
- **Thread-Safe**: All operations are thread-safe with proper locking

### Key Version Management

Each key has metadata including:
- **ID**: Unique identifier for the key
- **Method**: Signing method (HS256, RS256, etc.)
- **CreatedAt**: When the key was created
- **ExpiresAt**: When the key expires
- **IsActive**: Whether this is the current active key
- **TokenCount**: Number of tokens currently using this key

### Available Functions

#### TokenManager (Recommended)
- `NewTokenManager(config *TokenManagerConfig) *TokenManager` - Creates a new TokenManager

##### Builder Pattern
- `NewTokenManagerBuilder() *TokenManagerBuilder` - Creates a new TokenManagerBuilder
- `TokenManagerBuilder.WithJWTSecret(secret []byte) *TokenManagerBuilder` - Sets JWT secret
- `TokenManagerBuilder.WithJWTMethod(method SigningMethod) *TokenManagerBuilder` - Sets JWT method
- `TokenManagerBuilder.WithJWTKeyPair(keyPair *KeyPair) *TokenManagerBuilder` - Sets JWT key pair
- `TokenManagerBuilder.WithDefaultExpiration(duration time.Duration) *TokenManagerBuilder` - Sets default expiration
- `TokenManagerBuilder.WithRefreshConfig(config *TokenRefreshConfig) *TokenManagerBuilder` - Sets refresh token configuration
- `TokenManagerBuilder.Build() *TokenManager` - Builds the TokenManager

##### Method Chaining for Token Creation
- `TokenManager.NewToken() *TokenBuilder` - Creates a new TokenBuilder
- `TokenBuilder.WithIssuer(issuer string) *TokenBuilder` - Sets token issuer
- `TokenBuilder.WithSubject(subject string) *TokenBuilder` - Sets token subject
- `TokenBuilder.WithAudience(audience string) *TokenBuilder` - Sets token audience
- `TokenBuilder.WithExpiration(expiresAt time.Time) *TokenBuilder` - Sets token expiration
- `TokenBuilder.WithExpirationDuration(duration time.Duration) *TokenBuilder` - Sets token expiration as duration
- `TokenBuilder.WithNotBefore(notBefore time.Time) *TokenBuilder` - Sets token not before
- `TokenBuilder.WithIssuedAt(issuedAt time.Time) *TokenBuilder` - Sets token issued at
- `TokenBuilder.WithClaim(key string, value interface{}) *TokenBuilder` - Adds custom claim
- `TokenBuilder.WithClaims(claims map[string]interface{}) *TokenBuilder` - Adds multiple claims
- `TokenBuilder.CreateJWTWithHMAC(method SigningMethod) (*TokenResult, error)` - Creates JWT token with HMAC
- `TokenBuilder.CreateJWTWithKeyPair(keyPair KeyPair) (*TokenResult, error)` - Creates JWT token with key pair

##### General Methods (Auto-detect)
- `CreateJWTToken(req TokenRequest) (*TokenResult, error)` - Creates a JWT token (auto-detects method)
- `ValidateJWTToken(token string) (*TokenRequest, error)` - Validates a JWT token (auto-detects method)
- `ValidateToken(token string) (*TokenRequest, error)` - Auto-detects and validates JWT token
- `RefreshToken(refreshToken string) (*TokenResult, error)` - Refreshes an access token using a refresh token

##### TokenManager Validation Methods
- `ValidateJWTWithHMAC(token string, method SigningMethod) (*TokenRequest, error)` - Validates a JWT token with HMAC
- `ValidateJWTWithKeyPair(token string, keyPair KeyPair) (*TokenRequest, error)` - Validates a JWT token with key pair

#### KeyManager Functions
- `NewKeyManager(config KeyRotationConfig) (*KeyManager, error)` - Creates a new KeyManager
- `KeyManager.GenerateNewKey(method SigningMethod) (*KeyVersion, error)` - Generates a new key version
- `KeyManager.GetCurrentKey() (*KeyVersion, error)` - Gets the current active key
- `KeyManager.GetKeyByID(keyID string) (*KeyVersion, error)` - Gets a key by its ID
- `KeyManager.RotateKey(method SigningMethod) (*KeyVersion, error)` - Rotates to a new key
- `KeyManager.IncrementTokenCount(keyID string) error` - Increments token count for a key
- `KeyManager.DecrementTokenCount(keyID string) error` - Decrements token count for a key
- `KeyManager.GetKeyVersions() []*KeyVersion` - Gets all key versions
- `KeyManager.Stop()` - Stops the KeyManager and cleanup routines

#### Low-level JWT Functions
- `CreateJwtToken(req TokenRequest, secretKey []byte) (string, error)` - Creates a JWT token with HMAC
- `CreateJwtTokenWithMethod(req TokenRequest, key interface{}, method SigningMethod) (string, error)` - Creates a JWT token with specified method
- `CreateJwtTokenWithKeyPair(req TokenRequest, keyPair KeyPair) (string, error)` - Creates a JWT token with key pair
- `ParseJwtToken(tokenString string, secretKey []byte) (*jwt.Token, error)` - Parses a JWT token with HMAC
- `ParseJwtTokenWithMethod(tokenString string, key interface{}, method SigningMethod) (*jwt.Token, error)` - Parses a JWT token with specified method
- `ParseJwtTokenWithKeyPair(tokenString string, keyPair KeyPair) (*jwt.Token, error)` - Parses a JWT token with key pair

#### Key Generation Functions
- `GenerateRSAKeyPair(bits int) (*KeyPair, error)` - Generates RSA key pair (2048, 3072, 4096 bits)
- `GenerateECDSAKeyPair(curve elliptic.Curve) (*KeyPair, error)` - Generates ECDSA key pair (P-256, P-384, P-521)
- `GenerateEdDSAKeyPair() (*KeyPair, error)` - Generates EdDSA key pair (Ed25519)

## 🧪 Testing

The package includes comprehensive tests covering all functionality:

```bash
# Run all tests
go test -v

# Run specific test categories
go test -v -run "TestKeyManager"
go test -v -run "TestTokenBuilder"
go test -v -run "TestJWT"

# Run with coverage
go test -v -cover
```

### Test Coverage

- ✅ **JWT Token Tests**: 15+ tests covering all signing methods
- ✅ **Refresh Token Tests**: 10+ tests for refresh token functionality and security
- ✅ **KeyManager Tests**: 9+ tests for key rotation and persistence
- ✅ **TokenBuilder Tests**: 15+ tests for method chaining
- ✅ **Integration Tests**: End-to-end functionality testing
- ✅ **Edge Cases**: Error handling and boundary conditions

### Running Examples

```bash
# Basic example
go run cmd/example/main.go

# Key rotation example
go run cmd/key_rotation_example/main.go

# Refresh token examples
go run cmd/refresh_config_builder_example/main.go
go run cmd/max_refresh_attempts_example/main.go
go run cmd/embedded_refresh_example/main.go
```


### Development Setup

```bash
# Clone the repository
git clone https://github.com/bi0dread/tokeno.git
cd tokeno

# Install dependencies
go mod tidy

# Run tests
go test -v

# Run examples
go run cmd/example/main.go
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [golang-jwt/jwt](https://github.com/golang-jwt/jwt) for JWT implementation
- [golang.org/x/crypto](https://golang.org/x/crypto) for cryptographic functions
- The Go community for excellent tooling and libraries

---

<div align="center">

**Made with ❤️ by the Tokeno team**

[⭐ Star this repo](https://github.com/bi0dread/tokeno) • [🐛 Report Bug](https://github.com/bi0dread/tokeno/issues) • [💡 Request Feature](https://github.com/bi0dread/tokeno/issues)

</div>
