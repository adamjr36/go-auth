package tests

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
	"github.com/golang-jwt/jwt/v5"
)

// TestValidateTokenWithEmptyUserID tests validation of a token with an empty user ID
func TestValidateTokenWithEmptyUserID(t *testing.T) {
	// Create a mock store and auth instance
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Create a malformed token with empty user ID
	claims := jwt.MapClaims{
		"userId": "",
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Validate the token - should fail with empty user ID
	userId, err := authenticator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Errorf("Expected error for token with empty user ID, got nil")
	}
	if userId != "" {
		t.Errorf("Expected empty user ID, got %s", userId)
	}
}

// TestValidateTokenWithWrongAlgorithm tests validation of a token signed with wrong algorithm
func TestValidateTokenWithWrongAlgorithm(t *testing.T) {
	// Create a mock store and auth instance
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Create a token with different signing method
	claims := jwt.MapClaims{
		"userId": "user_123",
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Validate the token - should fail due to wrong algorithm
	userId, err := authenticator.ValidateToken(ctx, tokenString)
	if err == nil {
		t.Errorf("Expected error for token with wrong algorithm, got nil")
	}
	if userId != "" {
		t.Errorf("Expected empty user ID, got %s", userId)
	}
}

// TestRefreshTokenWithRevokedToken tests refreshing with an already revoked token
func TestRefreshTokenWithRevokedToken(t *testing.T) {
	// Create a mock store and auth instance
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Create a user and sign in to get tokens
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	_, _, refreshToken, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Manually revoke the refresh token
	err = authenticator.SignOut(ctx, refreshToken)
	if err != nil {
		t.Fatalf("Failed to revoke refresh token: %v", err)
	}

	// Try to refresh with the revoked token
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Expected error when refreshing with revoked token, got nil")
	}
}

// TestRefreshTokenWithMalformedToken tests refreshing with a malformed token
func TestRefreshTokenWithMalformedToken(t *testing.T) {
	// Create a mock store and auth instance
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Try to refresh with a malformed token
	_, _, _, err := authenticator.RefreshToken(ctx, "not-a-valid-token")
	if err == nil {
		t.Errorf("Expected error when refreshing with malformed token, got nil")
	}
}

// TestRefreshTokenWithDifferentAlgorithm tests refreshing with a token using different algorithm
func TestRefreshTokenWithDifferentAlgorithm(t *testing.T) {
	// Create a mock store and auth instance
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Create a token with different signing method
	claims := jwt.MapClaims{
		"userId": "user_123",
		"exp":    time.Now().Add(time.Hour).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("Failed to create test token: %v", err)
	}

	// Try to refresh with invalid algorithm token
	_, _, _, err = authenticator.RefreshToken(ctx, tokenString)
	if err == nil {
		t.Errorf("Expected error when refreshing with wrong algorithm token, got nil")
	}
}

// TestPasswordFunctions tests edge cases in password functions
func TestPasswordFunctions(t *testing.T) {
	// Test HashPassword with very long password
	longPassword := strings.Repeat("a", 72) // 72 chars, exceeds the limit
	_, err := auth.HashPassword(longPassword)
	if err == nil {
		t.Errorf("Expected error when hashing too long password, got nil")
	}

	// Test ComparePasswords with long password
	hash, _ := auth.HashPassword("validpassword")
	err = auth.ComparePasswords(hash, longPassword)
	if err == nil {
		t.Errorf("Expected error when comparing with too long password, got nil")
	}

	// Test ComparePasswords with incorrect password
	err = auth.ComparePasswords(hash, "wrongpassword")
	if err == nil {
		t.Errorf("Expected error when comparing with wrong password, got nil")
	}
}
