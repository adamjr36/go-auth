package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
	"github.com/golang-jwt/jwt/v5"
)

// MockErrorStore implements auth.Store but returns errors for specific operations to test error handling
type MockErrorStore struct {
	*MockStore
	shouldFailValidateRefreshToken bool
	shouldFailRevokeRefreshToken   bool
	shouldFailSetRefreshToken      bool
}

func NewMockErrorStore() *MockErrorStore {
	return &MockErrorStore{
		MockStore: NewMockStore(),
	}
}

// Override necessary methods to inject errors

func (m *MockErrorStore) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	if m.shouldFailValidateRefreshToken {
		return "", errors.New("mock ValidateRefreshToken error")
	}
	return m.MockStore.ValidateRefreshToken(ctx, refreshToken)
}

func (m *MockErrorStore) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if m.shouldFailRevokeRefreshToken {
		return errors.New("mock RevokeRefreshToken error")
	}
	return m.MockStore.RevokeRefreshToken(ctx, refreshToken)
}

func (m *MockErrorStore) SetRefreshToken(ctx context.Context, userID string, refreshToken string) error {
	if m.shouldFailSetRefreshToken {
		return errors.New("mock SetRefreshToken error")
	}
	return m.MockStore.SetRefreshToken(ctx, userID, refreshToken)
}

// TestRefreshTokenValidateError tests error handling when ValidateRefreshToken fails
func TestRefreshTokenValidateError(t *testing.T) {
	// Create a mock error store
	store := NewMockErrorStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up and sign in to get valid tokens
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

	// Set the store to fail on ValidateRefreshToken
	store.shouldFailValidateRefreshToken = true

	// Try to refresh the token, which should fail
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Expected error when ValidateRefreshToken fails, got nil")
	}
}

// TestRefreshTokenRevokeError tests error handling when RevokeRefreshToken fails
func TestRefreshTokenRevokeError(t *testing.T) {
	// Create a mock error store
	store := NewMockErrorStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up and sign in to get valid tokens
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

	// Set the store to fail on RevokeRefreshToken
	store.shouldFailRevokeRefreshToken = true

	// Try to refresh the token, which should fail
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Expected error when RevokeRefreshToken fails, got nil")
	}
}

// TestRefreshTokenSetError tests error handling when SetRefreshToken fails
func TestRefreshTokenSetError(t *testing.T) {
	// Create a mock error store
	store := NewMockErrorStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up and sign in to get valid tokens
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

	// Set the store to fail on SetRefreshToken
	store.shouldFailSetRefreshToken = true

	// Try to refresh the token, which should fail
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Expected error when SetRefreshToken fails, got nil")
	}
}

// TestRefreshTokenExpired tests refreshing with an expired refresh token
func TestRefreshTokenExpired(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create a custom config with very short expiry
	customConfig := auth.TokenConfig{
		AccessTokenExpiry:  5 * time.Second,
		RefreshTokenExpiry: 5 * time.Second, // Very short refresh token expiry
		Issuer:             "test-issuer",
	}

	authenticator := auth.NewWithConfig(secret, store, customConfig)
	ctx := context.Background()

	// Sign up and sign in to get tokens
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

	// Wait for the token to expire
	time.Sleep(6 * time.Second)

	// Try to refresh with the expired token
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Expected error when refreshing with expired token, got nil")
	}
}

// TestRefreshTokenWrongUser tests manipulating the user ID in a refresh token
func TestRefreshTokenWrongUser(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Sign up two users
	email1 := "user1@example.com"
	email2 := "user2@example.com"
	password := "secure-password-123"

	_, err := authenticator.SignUp(ctx, email1, password)
	if err != nil {
		t.Fatalf("Failed to sign up user1: %v", err)
	}

	userId2, err := authenticator.SignUp(ctx, email2, password)
	if err != nil {
		t.Fatalf("Failed to sign up user2: %v", err)
	}

	// Sign in as user1
	_, _, refreshToken, _, err := authenticator.SignIn(ctx, email1, password)
	if err != nil {
		t.Fatalf("Failed to sign in as user1: %v", err)
	}

	// Parse the refresh token to get the claims
	token, _ := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	claims := token.Claims.(jwt.MapClaims)

	// Create a modified token with user2's ID
	claims["userId"] = userId2
	claims["sub"] = userId2

	modifiedToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	modifiedTokenString, _ := modifiedToken.SignedString([]byte(secret))

	// Try to refresh with the modified token - this should fail due to token validation
	_, _, _, err = authenticator.RefreshToken(ctx, modifiedTokenString)
	if err == nil {
		t.Errorf("Expected error when refreshing with modified user ID, got nil")
	}
}
