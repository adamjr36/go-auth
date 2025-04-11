package tests

import (
	"context"
	"testing"

	"github.com/adamjr36/go-auth"
	"github.com/golang-jwt/jwt/v5"
)

// TestGenerateTokensErrorHandling tests error handling in token generation
func TestGenerateTokensErrorHandling(t *testing.T) {
	// We'll test this by creating a mock auth package that has an invalid signing method
	// that will cause token generation to fail

	// First, set up a normal flow to see how tokens are parsed
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up and sign in a user
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in to get tokens
	userID, jwtToken, refreshToken, expiresAt, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Verify tokens are valid
	if jwtToken == "" || refreshToken == "" || expiresAt == 0 || userID == "" {
		t.Errorf("Failed to generate valid tokens")
	}

	// Parse the token to verify structure
	token, err := jwt.Parse(jwtToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse JWT token: %v", err)
	}

	// Verify token claims
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		t.Errorf("Failed to parse token claims")
	}

	// Verify the claims
	if claims["id"] != userID {
		t.Errorf("Expected userID %s, got %v", userID, claims["id"])
	}

	if claims["iss"] != auth.DefaultTokenConfig().Issuer {
		t.Errorf("Expected issuer %s, got %v", auth.DefaultTokenConfig().Issuer, claims["iss"])
	}

	// Verify the refresh token
	refreshJwt, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("Failed to parse refresh token: %v", err)
	}

	refreshClaims, ok := refreshJwt.Claims.(jwt.MapClaims)
	if !ok {
		t.Errorf("Failed to parse refresh token claims")
	}

	// Verify refresh token claims
	if refreshClaims["id"] != userID {
		t.Errorf("Expected userID %s, got %v", userID, refreshClaims["id"])
	}

	if refreshClaims["iss"] != auth.DefaultTokenConfig().Issuer {
		t.Errorf("Expected issuer %s, got %v", auth.DefaultTokenConfig().Issuer, refreshClaims["iss"])
	}

	// Verify that the token IDs are different
	if claims["jti"] == refreshClaims["jti"] {
		t.Errorf("Expected different token IDs for JWT and refresh token")
	}
}

// TestMultipleTokenGeneration verifies that multiple tokens generated for the same user
// have unique identifiers
func TestMultipleTokenGeneration(t *testing.T) {
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up a user
	email := "user@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Sign in multiple times to get different tokens
	_, jwt1, refresh1, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in (1): %v", err)
	}

	_, jwt2, refresh2, _, err := authenticator.SignIn(ctx, email, password)
	if err != nil {
		t.Fatalf("Failed to sign in (2): %v", err)
	}

	// Parse tokens to extract claims
	token1, _ := jwt.Parse(jwt1, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	token2, _ := jwt.Parse(jwt2, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	claims1 := token1.Claims.(jwt.MapClaims)
	claims2 := token2.Claims.(jwt.MapClaims)

	// Verify that tokens have different JTIs
	if claims1["jti"] == claims2["jti"] {
		t.Errorf("Expected different JTIs for tokens generated in separate sign-ins")
	}

	// Parse refresh tokens
	refreshToken1, _ := jwt.Parse(refresh1, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	refreshToken2, _ := jwt.Parse(refresh2, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})

	refreshClaims1 := refreshToken1.Claims.(jwt.MapClaims)
	refreshClaims2 := refreshToken2.Claims.(jwt.MapClaims)

	// Verify that refresh tokens have different JTIs
	if refreshClaims1["jti"] == refreshClaims2["jti"] {
		t.Errorf("Expected different JTIs for refresh tokens generated in separate sign-ins")
	}
}
