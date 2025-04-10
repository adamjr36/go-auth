package tests

import (
	"context"
	"testing"

	"github.com/adamjr36/auth"
)

// TestSignUp tests the sign-up functionality
func TestSignUp(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)

	// Test successful sign-up
	ctx := context.Background()
	email := "user@example.com"
	password := "secure-password-123"

	userId, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Errorf("Failed to sign up user: %v", err)
	}

	if userId == "" {
		t.Errorf("User ID should not be empty after sign-up")
	}

	// Verify the user is in the store (using our mock implementation's internal state)
	if len(store.users) != 1 {
		t.Errorf("Expected 1 user in store, got %d", len(store.users))
	}

	// Verify the password is properly hashed
	storedPassword, exists := store.users[email]
	if !exists {
		t.Errorf("User not found in store after sign-up")
	}

	if storedPassword == password {
		t.Errorf("Password should be hashed in the store")
	}

	// Now try to sign up with the same email (should fail)
	_, err = authenticator.SignUp(ctx, email, password)
	if err == nil {
		t.Errorf("Sign-up with existing email should fail")
	}
}

// TestSignUpWithDifferentKeys tests signing up multiple users with different keys
func TestSignUpWithDifferentKeys(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up multiple users
	users := []struct {
		key      string
		password string
	}{
		{"user1@example.com", "password1"},
		{"user2@example.com", "password2"},
		{"user3@example.com", "password3"},
	}

	for _, user := range users {
		userId, err := authenticator.SignUp(ctx, user.key, user.password)
		if err != nil {
			t.Errorf("Failed to sign up user %s: %v", user.key, err)
		}

		if userId == "" {
			t.Errorf("User ID should not be empty after sign-up")
		}
	}

	// Verify we have the expected number of users
	if len(store.users) != len(users) {
		t.Errorf("Expected %d users in store, got %d", len(users), len(store.users))
	}
}

// TestSignUpWithInvalidInputs tests sign-up with invalid inputs
func TestSignUpWithInvalidInputs(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Test with empty key
	_, err := authenticator.SignUp(ctx, "", "password")
	if err == nil {
		t.Errorf("Sign-up with empty key should fail")
	}

	// Test with empty password
	_, err = authenticator.SignUp(ctx, "user@example.com", "")
	if err == nil {
		t.Errorf("Sign-up with empty password should fail")
	}
}
