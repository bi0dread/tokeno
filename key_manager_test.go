package tokeno

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewKeyManager(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory:     tempDir,
		RotationInterval: 1 * time.Hour,
		KeyLifetime:      24 * time.Hour,
		CleanupInterval:  30 * time.Minute,
		MaxKeyVersions:   5,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Verify default values were set
	if km.config.KeyDirectory != tempDir {
		t.Errorf("Expected KeyDirectory %s, got %s", tempDir, km.config.KeyDirectory)
	}
	if km.config.RotationInterval != 1*time.Hour {
		t.Errorf("Expected RotationInterval 1h, got %v", km.config.RotationInterval)
	}
	if km.config.KeyLifetime != 24*time.Hour {
		t.Errorf("Expected KeyLifetime 24h, got %v", km.config.KeyLifetime)
	}
	if km.config.CleanupInterval != 30*time.Minute {
		t.Errorf("Expected CleanupInterval 30m, got %v", km.config.CleanupInterval)
	}
	if km.config.MaxKeyVersions != 5 {
		t.Errorf("Expected MaxKeyVersions 5, got %d", km.config.MaxKeyVersions)
	}
}

func TestKeyManagerWithDefaults(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_defaults")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Verify default values
	if km.config.RotationInterval != 24*time.Hour {
		t.Errorf("Expected default RotationInterval 24h, got %v", km.config.RotationInterval)
	}
	if km.config.KeyLifetime != 7*24*time.Hour {
		t.Errorf("Expected default KeyLifetime 7d, got %v", km.config.KeyLifetime)
	}
	if km.config.CleanupInterval != 1*time.Hour {
		t.Errorf("Expected default CleanupInterval 1h, got %v", km.config.CleanupInterval)
	}
	if km.config.MaxKeyVersions != 10 {
		t.Errorf("Expected default MaxKeyVersions 10, got %d", km.config.MaxKeyVersions)
	}
}

func TestGenerateNewKey(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_generate")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
		KeyLifetime:  1 * time.Hour,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Test HMAC key generation
	hmacKey, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate HMAC key: %v", err)
	}

	if hmacKey.Method != SigningMethodHS256 {
		t.Errorf("Expected method HS256, got %s", hmacKey.Method)
	}
	if len(hmacKey.Key) != 32 {
		t.Errorf("Expected key length 32, got %d", len(hmacKey.Key))
	}
	if !hmacKey.IsActive {
		t.Error("Expected key to be active")
	}
	if hmacKey.TokenCount != 0 {
		t.Errorf("Expected token count 0, got %d", hmacKey.TokenCount)
	}

	// Test RSA key generation
	rsaKey, err := km.GenerateNewKey(SigningMethodRS256)
	if err != nil {
		t.Fatalf("Failed to generate RSA key: %v", err)
	}

	if rsaKey.Method != SigningMethodRS256 {
		t.Errorf("Expected method RS256, got %s", rsaKey.Method)
	}
	if rsaKey.KeyPair == nil {
		t.Error("Expected KeyPair to be set")
	}
	if !rsaKey.IsActive {
		t.Error("Expected key to be active")
	}

	// Verify previous key is deactivated
	if hmacKey.IsActive {
		t.Error("Expected previous key to be deactivated")
	}

	// Verify current key is the RSA key
	currentKey, err := km.GetCurrentKey()
	if err != nil {
		t.Fatalf("Failed to get current key: %v", err)
	}
	if currentKey.ID != rsaKey.ID {
		t.Errorf("Expected current key ID %s, got %s", rsaKey.ID, currentKey.ID)
	}
}

func TestKeyPersistence(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_persistence")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
		KeyLifetime:  1 * time.Hour,
	}

	// Create first KeyManager and generate a key
	km1, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}

	key1, err := km1.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}
	km1.Stop()

	// Create second KeyManager and verify key is loaded
	km2, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create second KeyManager: %v", err)
	}
	defer km2.Stop()

	loadedKey, err := km2.GetKeyByID(key1.ID)
	if err != nil {
		t.Fatalf("Failed to get loaded key: %v", err)
	}

	if loadedKey.ID != key1.ID {
		t.Errorf("Expected key ID %s, got %s", key1.ID, loadedKey.ID)
	}
	if loadedKey.Method != key1.Method {
		t.Errorf("Expected method %s, got %s", key1.Method, loadedKey.Method)
	}
	if !loadedKey.IsActive {
		t.Error("Expected loaded key to be active")
	}
}

func TestTokenCountTracking(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_counting")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
		KeyLifetime:  1 * time.Hour,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	key, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Test incrementing token count
	if err := km.IncrementTokenCount(key.ID); err != nil {
		t.Fatalf("Failed to increment token count: %v", err)
	}

	updatedKey, err := km.GetKeyByID(key.ID)
	if err != nil {
		t.Fatalf("Failed to get updated key: %v", err)
	}

	if updatedKey.TokenCount != 1 {
		t.Errorf("Expected token count 1, got %d", updatedKey.TokenCount)
	}

	// Test decrementing token count
	if err := km.DecrementTokenCount(key.ID); err != nil {
		t.Fatalf("Failed to decrement token count: %v", err)
	}

	updatedKey, err = km.GetKeyByID(key.ID)
	if err != nil {
		t.Fatalf("Failed to get updated key: %v", err)
	}

	if updatedKey.TokenCount != 0 {
		t.Errorf("Expected token count 0, got %d", updatedKey.TokenCount)
	}

	// Test decrementing below zero
	if err := km.DecrementTokenCount(key.ID); err != nil {
		t.Fatalf("Failed to decrement token count: %v", err)
	}

	updatedKey, err = km.GetKeyByID(key.ID)
	if err != nil {
		t.Fatalf("Failed to get updated key: %v", err)
	}

	if updatedKey.TokenCount != 0 {
		t.Errorf("Expected token count to remain 0, got %d", updatedKey.TokenCount)
	}
}

func TestKeyCleanup(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_cleanup")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory:    tempDir,
		KeyLifetime:     50 * time.Millisecond, // Very short lifetime
		CleanupInterval: 10 * time.Millisecond, // Frequent cleanup
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Generate a key
	key, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Deactivate the key to simulate it being replaced
	km.mutex.Lock()
	key.IsActive = false
	km.mutex.Unlock()

	// Wait for key to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup
	km.cleanupExpiredKeys()

	// Verify key is cleaned up
	_, err = km.GetKeyByID(key.ID)
	if err == nil {
		t.Error("Expected key to be cleaned up")
	}

	// Verify key file is deleted
	keyPath := filepath.Join(tempDir, key.ID+".json")
	if _, err := os.Stat(keyPath); err == nil {
		t.Error("Expected key file to be deleted")
	}
}

func TestKeyCleanupWithActiveTokens(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_cleanup_active")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory:    tempDir,
		KeyLifetime:     50 * time.Millisecond, // Very short lifetime
		CleanupInterval: 10 * time.Millisecond, // Frequent cleanup
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Generate a key
	key, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// Deactivate the key to simulate it being replaced
	km.mutex.Lock()
	key.IsActive = false
	km.mutex.Unlock()

	// Increment token count to simulate active tokens
	if err := km.IncrementTokenCount(key.ID); err != nil {
		t.Fatalf("Failed to increment token count: %v", err)
	}

	// Wait for key to expire
	time.Sleep(100 * time.Millisecond)

	// Manually trigger cleanup
	km.cleanupExpiredKeys()

	// Verify key is NOT cleaned up because it has active tokens
	_, err = km.GetKeyByID(key.ID)
	if err != nil {
		t.Error("Expected key to NOT be cleaned up due to active tokens")
	}

	// Decrement token count
	if err := km.DecrementTokenCount(key.ID); err != nil {
		t.Fatalf("Failed to decrement token count: %v", err)
	}

	// Trigger cleanup again
	km.cleanupExpiredKeys()

	// Now verify key is cleaned up
	_, err = km.GetKeyByID(key.ID)
	if err == nil {
		t.Error("Expected key to be cleaned up after token count reaches zero")
	}
}

func TestGetKeyVersions(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_versions")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
		KeyLifetime:  1 * time.Hour,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Generate multiple keys
	key1, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate key 1: %v", err)
	}

	key2, err := km.GenerateNewKey(SigningMethodHS384)
	if err != nil {
		t.Fatalf("Failed to generate key 2: %v", err)
	}

	key3, err := km.GenerateNewKey(SigningMethodHS512)
	if err != nil {
		t.Fatalf("Failed to generate key 3: %v", err)
	}

	// Get all key versions
	versions := km.GetKeyVersions()

	if len(versions) != 3 {
		t.Errorf("Expected 3 key versions, got %d", len(versions))
	}

	// Verify all keys are present
	keyIDs := make(map[string]bool)
	for _, version := range versions {
		keyIDs[version.ID] = true
	}

	if !keyIDs[key1.ID] {
		t.Error("Expected key 1 to be in versions")
	}
	if !keyIDs[key2.ID] {
		t.Error("Expected key 2 to be in versions")
	}
	if !keyIDs[key3.ID] {
		t.Error("Expected key 3 to be in versions")
	}

	// Verify only the last key is active
	activeCount := 0
	for _, version := range versions {
		if version.IsActive {
			activeCount++
		}
	}

	if activeCount != 1 {
		t.Errorf("Expected 1 active key, got %d", activeCount)
	}
}

func TestRotateKey(t *testing.T) {
	// Create a temporary directory for testing
	tempDir, err := os.MkdirTemp("", "key_manager_test_rotate")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	config := KeyRotationConfig{
		KeyDirectory: tempDir,
		KeyLifetime:  1 * time.Hour,
	}

	km, err := NewKeyManager(config)
	if err != nil {
		t.Fatalf("Failed to create KeyManager: %v", err)
	}
	defer km.Stop()

	// Generate initial key
	key1, err := km.GenerateNewKey(SigningMethodHS256)
	if err != nil {
		t.Fatalf("Failed to generate initial key: %v", err)
	}

	// Rotate to new key
	key2, err := km.RotateKey(SigningMethodHS512)
	if err != nil {
		t.Fatalf("Failed to rotate key: %v", err)
	}

	// Verify new key is active
	if !key2.IsActive {
		t.Error("Expected rotated key to be active")
	}

	// Verify old key is deactivated
	oldKey, err := km.GetKeyByID(key1.ID)
	if err != nil {
		t.Fatalf("Failed to get old key: %v", err)
	}
	if oldKey.IsActive {
		t.Error("Expected old key to be deactivated")
	}

	// Verify current key is the new one
	currentKey, err := km.GetCurrentKey()
	if err != nil {
		t.Fatalf("Failed to get current key: %v", err)
	}
	if currentKey.ID != key2.ID {
		t.Errorf("Expected current key ID %s, got %s", key2.ID, currentKey.ID)
	}
}
