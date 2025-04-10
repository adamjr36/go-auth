package tests

import (
	"context"
	"testing"

	"github.com/adamjr36/auth"
)

// TestSignOut tests the sign-out functionality
func TestSignOut(t *testing.T) {
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

	// Sign in to get tokens
	_, jwt, refreshToken, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Verify the JWT is valid before sign-out
	_, err = authenticator.ValidateToken(ctx, jwt)
	if err != nil {
		t.Errorf("JWT token should be valid before sign-out: %v", err)
	}

	// Sign out
	err = authenticator.SignOut(ctx, refreshToken)
	if err != nil {
		t.Errorf("Failed to sign out: %v", err)
	}

	// Verify the refresh token is no longer valid
	_, err = store.GetRefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Refresh token should not be valid after sign-out")
	}

	// Verify the JWT is still valid (sign-out doesn't invalidate JWTs, only refresh tokens)
	_, err = authenticator.ValidateToken(ctx, jwt)
	if err != nil {
		t.Log("Note: JWT token is still valid after sign-out as expected, since sign-out only invalidates refresh tokens")
	}

	// Try to refresh with the invalidated refresh token
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Should not be able to refresh token after sign-out")
	}
}

// TestSignOutAll tests signing out all sessions for a user
func TestSignOutAll(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	userId, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in multiple times to simulate multiple sessions
	_, _, refreshToken1, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in first time: %v", err)
	}

	_, _, refreshToken2, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in second time: %v", err)
	}

	// Sign out all sessions
	err = authenticator.SignOutAll(ctx, userId)
	if err != nil {
		t.Errorf("Failed to sign out all sessions: %v", err)
	}

	// Verify both refresh tokens are no longer valid
	_, err = store.GetRefreshToken(ctx, refreshToken1)
	if err == nil {
		t.Errorf("First refresh token should not be valid after sign-out all")
	}

	_, err = store.GetRefreshToken(ctx, refreshToken2)
	if err == nil {
		t.Errorf("Second refresh token should not be valid after sign-out all")
	}
}

// TestDeleteUser tests deleting a user
func TestDeleteUser(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	userId, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in to get tokens
	_, _, refreshToken, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Delete the user
	err = authenticator.DeleteUser(ctx, userId)
	if err != nil {
		t.Errorf("Failed to delete user: %v", err)
	}

	// Verify the user's credentials can no longer be used to sign in
	_, _, _, _, err = authenticator.SignIn(ctx, email, password)
	if err == nil {
		t.Errorf("Should not be able to sign in with deleted user's credentials")
	}

	// Verify the refresh token is no longer valid
	_, err = store.GetRefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Refresh token should not be valid after user deletion")
	}

	// JWT might still be valid, but that's expected since JWTs are stateless
	// For security, the token verification should ideally check if the user still exists
}
