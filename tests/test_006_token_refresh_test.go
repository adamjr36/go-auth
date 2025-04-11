package tests

import (
	"context"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
)

// TestTokenRefresh tests refreshing a token
func TestTokenRefresh(t *testing.T) {
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
	_, jwt, refreshToken, expiresAt, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Wait a bit to ensure the new token will have a different timestamp
	time.Sleep(100 * time.Millisecond)

	// Refresh the token
	newJwt, newRefreshToken, newExpiresAt, err := authenticator.RefreshToken(ctx, refreshToken)
	if err != nil {
		t.Errorf("Failed to refresh token: %v", err)
	}

	// Verify we got new tokens
	if newJwt == jwt {
		t.Errorf("New JWT should be different from old JWT")
	}

	if newRefreshToken == refreshToken {
		t.Errorf("New refresh token should be different from old refresh token")
	}

	if newExpiresAt <= expiresAt {
		t.Errorf("New expiration time should be later than old expiration time")
	}

	// Verify the old refresh token is no longer valid
	_, err = store.GetRefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Old refresh token should no longer be valid")
	}

	// Verify the new refresh token is valid
	storedToken, err := store.GetRefreshToken(ctx, newRefreshToken)
	if err != nil {
		t.Errorf("Failed to get new refresh token from store: %v", err)
	}

	if storedToken != newRefreshToken {
		t.Errorf("Stored refresh token does not match returned token")
	}

	// Verify we can validate the new JWT
	_, err = authenticator.ValidateToken(ctx, newJwt)
	if err != nil {
		t.Errorf("Failed to validate refreshed JWT: %v", err)
	}
}

// TestRefreshWithInvalidToken tests refreshing with an invalid token
func TestRefreshWithInvalidToken(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Test with empty refresh token
	_, _, _, err := authenticator.RefreshToken(ctx, "")
	if err == nil {
		t.Errorf("Refresh with empty token should fail")
	}

	// Test with malformed refresh token
	_, _, _, err = authenticator.RefreshToken(ctx, "not-a-valid-refresh-token")
	if err == nil {
		t.Errorf("Refresh with malformed token should fail")
	}
}

// TestRefreshWithRevokedToken tests refreshing with a revoked token
func TestRefreshWithRevokedToken(t *testing.T) {
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
	_, _, refreshToken, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Revoke the refresh token
	err = authenticator.SignOut(ctx, refreshToken)
	if err != nil {
		t.Fatalf("Failed to sign out: %v", err)
	}

	// Try to refresh with the revoked token
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Refresh with revoked token should fail")
	}
}

// TestMultipleRefreshes tests refreshing a token multiple times
func TestMultipleRefreshes(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator with short expiry for faster testing
	customConfig := auth.TokenConfig{
		AccessTokenExpiry:  5 * time.Second,
		RefreshTokenExpiry: 10 * time.Second,
		Issuer:             "test-issuer",
	}

	authenticator := auth.NewWithConfig(secret, store, customConfig)
	ctx := context.Background()

	// First sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in to get tokens
	_, _, refreshToken, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Refresh multiple times in sequence
	var currentRefreshToken = refreshToken
	for i := 0; i < 3; i++ {
		// Wait a bit between refreshes
		time.Sleep(100 * time.Millisecond)

		newJwt, newRefreshToken, _, err := authenticator.RefreshToken(ctx, currentRefreshToken)
		if err != nil {
			t.Errorf("Failed to refresh token (iteration %d): %v", i, err)
			break
		}

		// Verify we can validate the new JWT
		_, err = authenticator.ValidateToken(ctx, newJwt)
		if err != nil {
			t.Errorf("Failed to validate JWT after refresh (iteration %d): %v", i, err)
		}

		// Use the new refresh token for the next iteration
		currentRefreshToken = newRefreshToken
	}
}
