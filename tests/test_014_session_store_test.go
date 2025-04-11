package tests

import (
	"context"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
)

// TestSessionStoreMultipleSessions tests that a user can have multiple active sessions
func TestSessionStoreMultipleSessions(t *testing.T) {
	store := NewSessionStore()
	secret := "test-secret-key"
	auth := auth.New(secret, store)

	// Create a test user
	_, err := auth.SignUp(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	// Create first session
	sessionID1, jwt1, refreshToken1, _, err := auth.SignIn(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to sign in (first session): %v", err)
	}

	// Ensure there's a small delay between sessions to get different nonce values
	time.Sleep(10 * time.Millisecond)

	// Create second session
	sessionID2, jwt2, refreshToken2, _, err := auth.SignIn(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to sign in (second session): %v", err)
	}

	// Verify both sessions are valid and have different IDs
	if sessionID1 == sessionID2 {
		t.Error("Expected different session IDs for different sessions")
	}

	if refreshToken1 == refreshToken2 {
		t.Error("Expected different refresh tokens for different sessions")
	}

	// Verify both JWT tokens are valid
	validatedID1, err := auth.ValidateToken(context.Background(), jwt1)
	if err != nil {
		t.Fatalf("Failed to validate first token: %v", err)
	}
	if validatedID1 != sessionID1 {
		t.Errorf("Expected validated ID to match first session ID, got %s", validatedID1)
	}

	validatedID2, err := auth.ValidateToken(context.Background(), jwt2)
	if err != nil {
		t.Fatalf("Failed to validate second token: %v", err)
	}
	if validatedID2 != sessionID2 {
		t.Errorf("Expected validated ID to match second session ID, got %s", validatedID2)
	}

	// Verify both refresh tokens work
	newJWT1, newRefreshToken1, _, err := auth.RefreshToken(context.Background(), refreshToken1)
	if err != nil {
		t.Fatalf("Failed to refresh first token: %v", err)
	}

	newJWT2, newRefreshToken2, _, err := auth.RefreshToken(context.Background(), refreshToken2)
	if err != nil {
		t.Fatalf("Failed to refresh second token: %v", err)
	}

	// Verify new tokens are valid
	_, err = auth.ValidateToken(context.Background(), newJWT1)
	if err != nil {
		t.Fatalf("Failed to validate refreshed first token: %v", err)
	}

	_, err = auth.ValidateToken(context.Background(), newJWT2)
	if err != nil {
		t.Fatalf("Failed to validate refreshed second token: %v", err)
	}

	// Sign out from first session
	err = auth.SignOut(context.Background(), newRefreshToken1)
	if err != nil {
		t.Fatalf("Failed to sign out from first session: %v", err)
	}

	// Verify first session is revoked but second still works
	_, _, _, err = auth.RefreshToken(context.Background(), newRefreshToken1)
	if err == nil {
		t.Error("Expected error when using revoked refresh token")
	}

	_, _, _, err = auth.RefreshToken(context.Background(), newRefreshToken2)
	if err != nil {
		t.Fatalf("Failed to refresh second token after first session sign out: %v", err)
	}

	// Sign out all sessions
	err = auth.SignOutAll(context.Background(), sessionID2)
	if err != nil {
		t.Fatalf("Failed to sign out all sessions: %v", err)
	}

	// Verify both sessions are revoked
	_, _, _, err = auth.RefreshToken(context.Background(), newRefreshToken2)
	if err == nil {
		t.Error("Expected error when using revoked refresh token after sign out all")
	}
}

// TestSessionStoreRevocation tests that revoking a session properly marks it as revoked
func TestSessionStoreRevocation(t *testing.T) {
	store := NewSessionStore()
	secret := "test-secret-key"
	auth := auth.New(secret, store)

	// Create a test user and session
	_, err := auth.SignUp(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}

	sessionID, _, refreshToken, _, err := auth.SignIn(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Revoke the session
	err = store.RevokeAllRefreshTokens(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("Failed to revoke session: %v", err)
	}

	// Verify the session is revoked
	_, err = store.GetRefreshToken(context.Background(), refreshToken)
	if err == nil {
		t.Error("Expected error when getting revoked refresh token")
	}
}
