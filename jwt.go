package tokeno

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/ed25519"
)

// SigningMethod represents the type of signing method
type SigningMethod string

const (
	// HMAC signing methods
	SigningMethodHS256 SigningMethod = "HS256"
	SigningMethodHS384 SigningMethod = "HS384"
	SigningMethodHS512 SigningMethod = "HS512"

	// RSA signing methods
	SigningMethodRS256 SigningMethod = "RS256"
	SigningMethodRS384 SigningMethod = "RS384"
	SigningMethodRS512 SigningMethod = "RS512"

	// ECDSA signing methods
	SigningMethodES256 SigningMethod = "ES256"
	SigningMethodES384 SigningMethod = "ES384"
	SigningMethodES512 SigningMethod = "ES512"

	// EdDSA signing method
	SigningMethodEdDSA SigningMethod = "EdDSA"
)

// KeyPair represents a public/private key pair
type KeyPair struct {
	PrivateKey interface{}
	PublicKey  interface{}
	Method     SigningMethod
}

// TokenRequest represents the request structure for creating a JWT token
type TokenRequest struct {
	Issuer       string                 `json:"issuer"`
	Subject      string                 `json:"subject"`
	Audience     string                 `json:"audience"`
	ExpiresAt    time.Time              `json:"expires_at"`
	NotBefore    time.Time              `json:"not_before"`
	IssuedAt     time.Time              `json:"issued_at"`
	CustomClaims map[string]interface{} `json:"custom_claims"`
}

// CreateJwtToken creates a JWT token from the provided TokenRequest
func CreateJwtToken(req TokenRequest, secretKey []byte) (string, error) {
	// Create a new token with the signing method
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"iss": req.Issuer,           // Issuer
		"sub": req.Subject,          // Subject
		"aud": req.Audience,         // Audience
		"exp": req.ExpiresAt.Unix(), // Expiration time
		"nbf": req.NotBefore.Unix(), // Not before
		"iat": req.IssuedAt.Unix(),  // Issued at
	})

	// Add custom claims if provided
	for key, value := range req.CustomClaims {
		token.Claims.(jwt.MapClaims)[key] = value
	}

	// Sign the token with the secret key
	tokenString, err := token.SignedString(secretKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// ParseJwtToken parses and validates a JWT token
func ParseJwtToken(tokenString string, secretKey []byte) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return secretKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil
}

// ValidateTokenClaims validates if the token claims are valid
func ValidateTokenClaims(token *jwt.Token) error {
	if !token.Valid {
		return fmt.Errorf("token is not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return fmt.Errorf("invalid token claims")
	}

	// Check if required claims exist
	requiredClaims := []string{"iss", "sub", "aud", "exp", "nbf", "iat"}
	for _, claim := range requiredClaims {
		if _, exists := claims[claim]; !exists {
			return fmt.Errorf("missing required claim: %s", claim)
		}
	}

	return nil
}

// CreateJwtTokenWithMethod creates a JWT token using the specified signing method
func CreateJwtTokenWithMethod(req TokenRequest, key interface{}, method SigningMethod) (string, error) {
	var signingMethod jwt.SigningMethod

	switch method {
	case SigningMethodHS256:
		signingMethod = jwt.SigningMethodHS256
	case SigningMethodHS384:
		signingMethod = jwt.SigningMethodHS384
	case SigningMethodHS512:
		signingMethod = jwt.SigningMethodHS512
	case SigningMethodRS256:
		signingMethod = jwt.SigningMethodRS256
	case SigningMethodRS384:
		signingMethod = jwt.SigningMethodRS384
	case SigningMethodRS512:
		signingMethod = jwt.SigningMethodRS512
	case SigningMethodES256:
		signingMethod = jwt.SigningMethodES256
	case SigningMethodES384:
		signingMethod = jwt.SigningMethodES384
	case SigningMethodES512:
		signingMethod = jwt.SigningMethodES512
	case SigningMethodEdDSA:
		signingMethod = jwt.SigningMethodEdDSA
	default:
		return "", fmt.Errorf("unsupported signing method: %s", method)
	}

	// Create a new token with the specified signing method
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"iss": req.Issuer,           // Issuer
		"sub": req.Subject,          // Subject
		"aud": req.Audience,         // Audience
		"exp": req.ExpiresAt.Unix(), // Expiration time
		"nbf": req.NotBefore.Unix(), // Not before
		"iat": req.IssuedAt.Unix(),  // Issued at
	})

	// Add custom claims if provided
	for key, value := range req.CustomClaims {
		token.Claims.(jwt.MapClaims)[key] = value
	}

	// Sign the token with the provided key
	tokenString, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, nil
}

// CreateJwtTokenWithKeyPair creates a JWT token using a KeyPair
func CreateJwtTokenWithKeyPair(req TokenRequest, keyPair KeyPair) (string, error) {
	return CreateJwtTokenWithMethod(req, keyPair.PrivateKey, keyPair.Method)
}

// ParseJwtTokenWithMethod parses and validates a JWT token using the specified method
func ParseJwtTokenWithMethod(tokenString string, key interface{}, method SigningMethod) (*jwt.Token, error) {
	var signingMethod jwt.SigningMethod

	switch method {
	case SigningMethodHS256:
		signingMethod = jwt.SigningMethodHS256
	case SigningMethodHS384:
		signingMethod = jwt.SigningMethodHS384
	case SigningMethodHS512:
		signingMethod = jwt.SigningMethodHS512
	case SigningMethodRS256:
		signingMethod = jwt.SigningMethodRS256
	case SigningMethodRS384:
		signingMethod = jwt.SigningMethodRS384
	case SigningMethodRS512:
		signingMethod = jwt.SigningMethodRS512
	case SigningMethodES256:
		signingMethod = jwt.SigningMethodES256
	case SigningMethodES384:
		signingMethod = jwt.SigningMethodES384
	case SigningMethodES512:
		signingMethod = jwt.SigningMethodES512
	case SigningMethodEdDSA:
		signingMethod = jwt.SigningMethodEdDSA
	default:
		return nil, fmt.Errorf("unsupported signing method: %s", method)
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if token.Method != signingMethod {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil
}

// ParseJwtTokenWithKeyPair parses and validates a JWT token using a KeyPair
func ParseJwtTokenWithKeyPair(tokenString string, keyPair KeyPair) (*jwt.Token, error) {
	return ParseJwtTokenWithMethod(tokenString, keyPair.PublicKey, keyPair.Method)
}

// GenerateRSAKeyPair generates an RSA key pair
func GenerateRSAKeyPair(bits int) (*KeyPair, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	var method SigningMethod
	switch bits {
	case 2048:
		method = SigningMethodRS256
	case 3072:
		method = SigningMethodRS384
	case 4096:
		method = SigningMethodRS512
	default:
		method = SigningMethodRS256
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Method:     method,
	}, nil
}

// GenerateECDSAKeyPair generates an ECDSA key pair
func GenerateECDSAKeyPair(curve elliptic.Curve) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	var method SigningMethod
	switch curve {
	case elliptic.P256():
		method = SigningMethodES256
	case elliptic.P384():
		method = SigningMethodES384
	case elliptic.P521():
		method = SigningMethodES512
	default:
		method = SigningMethodES256
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Method:     method,
	}, nil
}

// GenerateEdDSAKeyPair generates an EdDSA key pair
func GenerateEdDSAKeyPair() (*KeyPair, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate EdDSA key: %w", err)
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Method:     SigningMethodEdDSA,
	}, nil
}

// LoadRSAKeyPairFromPEM loads RSA key pair from PEM encoded data
func LoadRSAKeyPairFromPEM(privateKeyPEM, publicKeyPEM []byte) (*KeyPair, error) {
	// Parse private key
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse public key
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPublicKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not RSA")
	}

	// Determine method based on key size
	var method SigningMethod
	switch privateKey.N.BitLen() {
	case 2048:
		method = SigningMethodRS256
	case 3072:
		method = SigningMethodRS384
	case 4096:
		method = SigningMethodRS512
	default:
		method = SigningMethodRS256
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  rsaPublicKey,
		Method:     method,
	}, nil
}

// LoadECDSAKeyPairFromPEM loads ECDSA key pair from PEM encoded data
func LoadECDSAKeyPairFromPEM(privateKeyPEM, publicKeyPEM []byte) (*KeyPair, error) {
	// Parse private key
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Parse public key
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not ECDSA")
	}

	// Determine method based on curve
	var method SigningMethod
	switch privateKey.Curve {
	case elliptic.P256():
		method = SigningMethodES256
	case elliptic.P384():
		method = SigningMethodES384
	case elliptic.P521():
		method = SigningMethodES512
	default:
		method = SigningMethodES256
	}

	return &KeyPair{
		PrivateKey: privateKey,
		PublicKey:  ecdsaPublicKey,
		Method:     method,
	}, nil
}

// LoadEdDSAKeyPairFromPEM loads EdDSA key pair from PEM encoded data
func LoadEdDSAKeyPairFromPEM(privateKeyPEM, publicKeyPEM []byte) (*KeyPair, error) {
	// Parse private key
	privateKeyBlock, _ := pem.Decode(privateKeyPEM)
	if privateKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode private key PEM")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519PrivateKey, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not Ed25519")
	}

	// Parse public key
	publicKeyBlock, _ := pem.Decode(publicKeyPEM)
	if publicKeyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key PEM")
	}

	publicKey, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519PublicKey, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("public key is not Ed25519")
	}

	return &KeyPair{
		PrivateKey: ed25519PrivateKey,
		PublicKey:  ed25519PublicKey,
		Method:     SigningMethodEdDSA,
	}, nil
}
