package tests

import (
	"context"
	"testing"
	"time"

	"github.com/adamjr36/auth"
)

// TestTokenValidation tests the validation of JWT tokens
func TestTokenValidation(t *testing.T) {
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

	// Sign in to get a valid token
	_, jwt, _, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Test validation of a valid token
	userId, err := authenticator.ValidateToken(ctx, jwt)
	if err != nil {
		t.Errorf("Failed to validate valid token: %v", err)
	}

	if userId != expectedUserId {
		t.Errorf("Expected user ID %s, got %s", expectedUserId, userId)
	}
}

// TestInvalidTokenValidation tests validation of invalid tokens
func TestInvalidTokenValidation(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Test with empty token
	_, err := authenticator.ValidateToken(ctx, "")
	if err == nil {
		t.Errorf("Validation of empty token should fail")
	}

	// Test with malformed token
	_, err = authenticator.ValidateToken(ctx, "not-a-valid-jwt-token")
	if err == nil {
		t.Errorf("Validation of malformed token should fail")
	}

	// Test with wrong signature
	// First create a token with one secret
	store1 := NewMockStore()
	auth1 := auth.New("secret1", store1)

	// Sign up and sign in to get a token
	_, err = auth1.SignUp(ctx, "user@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	_, jwt, _, _, err := auth1.SignIn(ctx, "user@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Then try to validate it with a different secret
	auth2 := auth.New("secret2", store)
	_, err = auth2.ValidateToken(ctx, jwt)
	if err == nil {
		t.Errorf("Validation of token with wrong signature should fail")
	}
}

// TestTokenWithDifferentCustomConfig tests token generation and validation with custom config
func TestTokenWithDifferentCustomConfig(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator with shorter token expiry
	customConfig := auth.TokenConfig{
		AccessTokenExpiry:  5 * time.Second, // very short expiry
		RefreshTokenExpiry: 10 * time.Second,
		Issuer:             "test-issuer",
	}

	authenticator := auth.NewWithConfig(secret, store, customConfig)
	ctx := context.Background()

	// Sign up and sign in
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	_, jwt, _, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Validate token immediately (should succeed)
	_, err = authenticator.ValidateToken(ctx, jwt)
	if err != nil {
		t.Errorf("Failed to validate token immediately: %v", err)
	}

	// Wait for token to expire
	time.Sleep(6 * time.Second)

	// Try to validate expired token
	_, err = authenticator.ValidateToken(ctx, jwt)
	if err == nil {
		t.Errorf("Validation of expired token should fail")
	}
}
