package tests

import (
	"testing"

	"github.com/adamjr36/go-auth"
)

// TestPasswordHashing tests the password hashing functionality
func TestPasswordHashing(t *testing.T) {
	password := "secure-password-123"

	// Test password hashing
	hashedPassword, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Failed to hash password: %v", err)
	}

	if hashedPassword == password {
		t.Errorf("Hashed password should not be equal to original password")
	}

	// Verify that the same password hashed twice gives different outputs (due to salt)
	hashedPassword2, err := auth.HashPassword(password)
	if err != nil {
		t.Errorf("Failed to hash password the second time: %v", err)
	}

	if hashedPassword == hashedPassword2 {
		t.Errorf("Two hashes of the same password should not be identical due to salt")
	}
}

// TestPasswordComparison tests the password comparison functionality
func TestPasswordComparison(t *testing.T) {
	correctPassword := "secure-password-123"
	incorrectPassword := "wrong-password-456"

	// Hash the correct password
	hashedPassword, err := auth.HashPassword(correctPassword)
	if err != nil {
		t.Errorf("Failed to hash password: %v", err)
	}

	// Test valid password comparison
	err = auth.ComparePasswords(hashedPassword, correctPassword)
	if err != nil {
		t.Errorf("Password comparison failed for correct password: %v", err)
	}

	// Test invalid password comparison
	err = auth.ComparePasswords(hashedPassword, incorrectPassword)
	if err == nil {
		t.Errorf("Password comparison should fail for incorrect password")
	}
}

// TestPasswordEdgeCases tests edge cases with passwords
func TestPasswordEdgeCases(t *testing.T) {
	// Test empty password
	emptyPassword := ""
	hashedEmpty, err := auth.HashPassword(emptyPassword)
	if err != nil {
		t.Errorf("Failed to hash empty password: %v", err)
	}

	err = auth.ComparePasswords(hashedEmpty, emptyPassword)
	if err != nil {
		t.Errorf("Password comparison failed for empty password: %v", err)
	}

	// Test very long password (should still work)
	longPassword := "this-is-a-very-long-password-that-exceeds-typical-input-limits-but-should-still-be-hashable-and-comparable-in-the-system-with-no-issues"
	hashedLong, err := auth.HashPassword(longPassword)
	if err != nil {
		t.Errorf("Failed to hash long password: %v", err)
	}

	err = auth.ComparePasswords(hashedLong, longPassword)
	if err != nil {
		t.Errorf("Password comparison failed for long password: %v", err)
	}
}
