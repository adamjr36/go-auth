package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
)

// ErroringStore implements the auth.Store interface but returns errors for testing
type ErroringStore struct {
	*MockStore
	shouldError bool
}

func NewErroringStore() *ErroringStore {
	return &ErroringStore{
		MockStore:   NewMockStore(),
		shouldError: false,
	}
}

func (s *ErroringStore) SetError(shouldError bool) {
	s.shouldError = shouldError
}

func (s *ErroringStore) CreateUser(ctx context.Context, key string, password string) (string, error) {
	if s.shouldError {
		return "", errors.New("simulated error in CreateUser")
	}
	return s.MockStore.CreateUser(ctx, key, password)
}

func (s *ErroringStore) GetUserAuth(ctx context.Context, key string) (string, string, error) {
	if s.shouldError {
		return "", "", errors.New("simulated error in GetUserAuth")
	}
	return s.MockStore.GetUserAuth(ctx, key)
}

func (s *ErroringStore) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	if s.shouldError {
		return "", errors.New("simulated error in ValidateRefreshToken")
	}
	return s.MockStore.ValidateRefreshToken(ctx, refreshToken)
}

func (s *ErroringStore) SetRefreshToken(ctx context.Context, userID string, refreshToken string) error {
	if s.shouldError {
		return errors.New("simulated error in SetRefreshToken")
	}
	return s.MockStore.SetRefreshToken(ctx, userID, refreshToken)
}

func (s *ErroringStore) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	if s.shouldError {
		return errors.New("simulated error in RevokeRefreshToken")
	}
	return s.MockStore.RevokeRefreshToken(ctx, refreshToken)
}

func (s *ErroringStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	if s.shouldError {
		return errors.New("simulated error in RevokeAllRefreshTokens")
	}
	return s.MockStore.RevokeAllRefreshTokens(ctx, userID)
}

func (s *ErroringStore) DeleteUser(ctx context.Context, userID string) error {
	if s.shouldError {
		return errors.New("simulated error in DeleteUser")
	}
	return s.MockStore.DeleteUser(ctx, userID)
}

// TestStorageErrors tests how the auth module handles storage errors
func TestStorageErrors(t *testing.T) {
	// Create an erroring store
	store := NewErroringStore()
	secret := "test-secret-key"

	// Create an authenticator
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Test sign-up failure
	store.SetError(true)
	_, err := authenticator.SignUp(ctx, "user@example.com", "password")
	if err == nil {
		t.Errorf("Sign-up should fail when store.CreateUser fails")
	}

	// Prepare for sign-in test
	store.SetError(false)
	userId, err := authenticator.SignUp(ctx, "user@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to sign up user: %v", err)
	}

	// Test sign-in failure
	store.SetError(true)
	_, _, _, _, err = authenticator.SignIn(ctx, "user@example.com", "password")
	if err == nil {
		t.Errorf("Sign-in should fail when store.GetUserAuth fails")
	}

	// Test token refresh failure
	store.SetError(false)
	_, _, refreshToken, _, err := authenticator.SignIn(ctx, "user@example.com", "password")
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	store.SetError(true)
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err == nil {
		t.Errorf("Token refresh should fail when store.ValidateRefreshToken fails")
	}

	// Test sign-out failure
	store.SetError(true)
	err = authenticator.SignOut(ctx, refreshToken)
	if err == nil {
		t.Errorf("Sign-out should fail when store.RevokeRefreshToken fails")
	}

	// Test delete user failure
	store.SetError(true)
	err = authenticator.DeleteUser(ctx, userId)
	if err == nil {
		t.Errorf("Delete user should fail when store.DeleteUser fails")
	}
}

// TestConcurrentTokenRefresh tests refreshing tokens concurrently
func TestConcurrentTokenRefresh(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	secret := "test-secret-key"

	// Create an authenticator with custom config
	customConfig := auth.TokenConfig{
		AccessTokenExpiry:  5 * time.Second,
		RefreshTokenExpiry: 10 * time.Second,
		Issuer:             "test-issuer",
	}

	authenticator := auth.NewWithConfig(secret, store, customConfig)
	ctx := context.Background()

	// Sign up a user
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

	// Simulate concurrent token refreshes
	refreshResults := make(chan error, 2)

	for i := 0; i < 2; i++ {
		go func(i int) {
			_, _, _, err := authenticator.RefreshToken(ctx, refreshToken)
			refreshResults <- err
		}(i)
	}

	// Check results - one should succeed and one should fail
	// since the first refresh invalidates the token for the second
	var successCount, failCount int
	for i := 0; i < 2; i++ {
		err := <-refreshResults
		if err == nil {
			successCount++
		} else {
			failCount++
		}
	}

	// At least one should fail since the token gets replaced after first refresh
	if failCount == 0 {
		t.Errorf("Expected at least one refresh to fail when used concurrently")
	}
}

// TestEmptySecret tests using an empty secret key
func TestEmptySecret(t *testing.T) {
	// Create a mock store
	store := NewMockStore()
	emptySecret := ""

	// Create an authenticator with empty secret
	authenticator := auth.New(emptySecret, store)
	ctx := context.Background()

	// Sign up should work
	_, err := authenticator.SignUp(ctx, "user@example.com", "password")
	if err != nil {
		t.Logf("Sign-up with empty secret failed: %v", err)
	}

	// Sign in - JWT generation might fail with empty secret
	_, jwt, refreshToken, _, err := authenticator.SignIn(ctx, "user@example.com", "password")
	if err != nil {
		t.Logf("Sign-in with empty secret failed: %v", err)
		return
	}

	// If we got a token, try to validate it
	_, err = authenticator.ValidateToken(ctx, jwt)
	if err != nil {
		t.Logf("Token validation with empty secret failed: %v", err)
	}

	// Try to refresh token
	_, _, _, err = authenticator.RefreshToken(ctx, refreshToken)
	if err != nil {
		t.Logf("Token refresh with empty secret failed: %v", err)
	}
}
