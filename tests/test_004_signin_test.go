package tests

import (
	"context"
	"testing"

	"github.com/adamjr36/go-auth"
)

// TestSignIn tests the sign-in functionality
func TestSignIn(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	expectedUserId, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Test successful sign-in
	userId, jwt, refreshToken, expiresAt, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Errorf("Failed to sign in: %v", err)
	}

	// Verify the returned values
	if userId != expectedUserId {
		t.Errorf("Expected user ID %s, got %s", expectedUserId, userId)
	}

	if jwt == "" {
		t.Errorf("JWT token should not be empty")
	}

	if refreshToken == "" {
		t.Errorf("Refresh token should not be empty")
	}

	if expiresAt <= 0 {
		t.Errorf("Token expiration time should be in the future")
	}

	// Verify the refresh token is stored
	storedToken, err := store.ValidateRefreshToken(ctx, refreshToken)
	if err != nil {
		t.Errorf("Failed to get refresh token from store: %v", err)
	}

	if storedToken != refreshToken {
		t.Errorf("Stored refresh token does not match returned token")
	}
}

// TestSignInWithInvalidCredentials tests sign-in with invalid credentials
func TestSignInWithInvalidCredentials(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Test sign-in with wrong password
	_, _, _, _, err = authenticator.SignIn(ctx, email, "wrong-password")
	if err == nil {
		t.Errorf("Sign-in with wrong password should fail")
	}

	// Test sign-in with non-existent user
	_, _, _, _, err = authenticator.SignIn(ctx, "nonexistent@example.com", password)
	if err == nil {
		t.Errorf("Sign-in with non-existent user should fail")
	}
}

// TestMultipleSignIns tests multiple sign-ins for the same user
func TestMultipleSignIns(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in first time
	userId1, jwt1, refreshToken1, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in first time: %v", err)
	}

	// Sign in second time
	userId2, jwt2, refreshToken2, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Errorf("Failed to sign in second time: %v", err)
	}

	// User ID should be the same for both sign-ins
	if userId1 != userId2 {
		t.Errorf("User IDs should be the same for multiple sign-ins")
	}

	// Tokens should be different
	if jwt1 == jwt2 {
		t.Errorf("JWT tokens should be different for different sign-ins")
	}

	if refreshToken1 == refreshToken2 {
		t.Errorf("Refresh tokens should be different for different sign-ins")
	}

	// Both tokens should be valid in the store
	_, err = store.ValidateRefreshToken(ctx, refreshToken1)
	if err != nil {
		t.Errorf("First refresh token should be valid: %v", err)
	}

	_, err = store.ValidateRefreshToken(ctx, refreshToken2)
	if err != nil {
		t.Errorf("Second refresh token should be valid: %v", err)
	}
}
