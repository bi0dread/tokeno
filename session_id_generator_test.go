package tokeno

import (
	"testing"
)

func TestGenerateSessionID(t *testing.T) {
	// Test 1: Generate a single session ID
	t.Run("Generate single session ID", func(t *testing.T) {
		sessionID := GenerateSessionID()
		if sessionID == "" {
			t.Error("Generated session ID should not be empty")
		}
		if len(sessionID) != 32 { // 16 bytes = 32 hex characters
			t.Errorf("Expected session ID length 32, got %d", len(sessionID))
		}
		t.Logf("Generated session ID: %s", sessionID)
	})

	// Test 2: Generate multiple session IDs and ensure they're unique
	t.Run("Generate multiple unique session IDs", func(t *testing.T) {
		sessionIDs := make(map[string]bool)
		for i := 0; i < 100; i++ {
			sessionID := GenerateSessionID()
			if sessionIDs[sessionID] {
				t.Errorf("Duplicate session ID generated: %s", sessionID)
			}
			sessionIDs[sessionID] = true
		}
		t.Logf("Generated %d unique session IDs", len(sessionIDs))
	})

	// Test 3: Test session ID format (should be hex)
	t.Run("Session ID format validation", func(t *testing.T) {
		sessionID := GenerateSessionID()
		// Check that it's a valid hex string
		for _, char := range sessionID {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				t.Errorf("Session ID contains non-hex character: %c", char)
			}
		}
	})

	// Test 4: Test that session IDs are consistent in length
	t.Run("Session ID length consistency", func(t *testing.T) {
		for i := 0; i < 10; i++ {
			sessionID := GenerateSessionID()
			if len(sessionID) != 32 {
				t.Errorf("Expected session ID length 32, got %d for ID: %s", len(sessionID), sessionID)
			}
		}
	})
}
