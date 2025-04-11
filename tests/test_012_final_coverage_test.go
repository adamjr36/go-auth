package tests

import (
	"context"
	"errors"
	"testing"

	"github.com/adamjr36/go-auth"
)

// Custom mock store to simulate store errors
type MockSignInErrorStore struct {
	*MockStore
	shouldFailGetUserAuth bool
}

func NewMockSignInErrorStore() *MockSignInErrorStore {
	return &MockSignInErrorStore{
		MockStore: NewMockStore(),
	}
}

func (m *MockSignInErrorStore) GetUserAuth(ctx context.Context, key string) (string, string, error) {
	if m.shouldFailGetUserAuth {
		return "", "", errors.New("mock GetUserAuth error")
	}
	return m.MockStore.GetUserAuth(ctx, key)
}

// TestSignInWithStoreError tests error handling when the store returns an error during sign in
func TestSignInWithStoreError(t *testing.T) {
	// Create a mock store that will fail on GetUserAuth
	store := NewMockSignInErrorStore()
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

	// Set the store to fail on GetUserAuth
	store.shouldFailGetUserAuth = true

	// Try to sign in, which should fail
	_, _, _, _, err = authenticator.SignIn(ctx, email, password)
	if err == nil {
		t.Errorf("Expected error when GetUserAuth fails, got nil")
	}
}

// TestSignInTokenGenerationEdgeCases tests edge cases in token generation during sign in
// We set this up by creating a mock bcrypt function that fails
type MockBcryptErrorStore struct {
	*MockStore
	shouldFailSetRefreshToken bool
}

func NewMockBcryptErrorStore() *MockBcryptErrorStore {
	return &MockBcryptErrorStore{
		MockStore: NewMockStore(),
	}
}

func (m *MockBcryptErrorStore) SetRefreshToken(ctx context.Context, userID string, refreshToken string) error {
	if m.shouldFailSetRefreshToken {
		return errors.New("mock SetRefreshToken error")
	}
	return m.MockStore.SetRefreshToken(ctx, userID, refreshToken)
}

// TestSignInWithSetRefreshTokenError tests error handling when SetRefreshToken fails during sign in
func TestSignInWithSetRefreshTokenError(t *testing.T) {
	// Create a mock store that will fail on SetRefreshToken
	store := NewMockBcryptErrorStore()
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

	// Set the store to fail on SetRefreshToken
	store.shouldFailSetRefreshToken = true

	// Try to sign in, which should fail when setting the refresh token
	_, _, _, _, err = authenticator.SignIn(ctx, email, password)
	if err == nil {
		t.Errorf("Expected error when SetRefreshToken fails, got nil")
	}
}

// TestHashPasswordErrorHandling tests the error handling in HashPassword function
func TestHashPasswordErrorHandling(t *testing.T) {
	// We can't easily inject a bcrypt error, so we'll test the edge cases

	// Test empty password
	_, err := auth.HashPassword("")
	if err != nil {
		t.Errorf("Unexpected error with empty password: %v", err)
	}

	// Test valid password lengths
	_, err = auth.HashPassword("a")
	if err != nil {
		t.Errorf("Unexpected error with 1 character password: %v", err)
	}

	// Test with exactly 71 characters (limit)
	pwd71 := make([]byte, 71)
	for i := range pwd71 {
		pwd71[i] = 'a'
	}
	_, err = auth.HashPassword(string(pwd71))
	if err != nil {
		t.Errorf("Unexpected error with 71 character password: %v", err)
	}

	// Test with special characters
	_, err = auth.HashPassword("!@#$%^&*()_+-=[]{}|;':\",./<>?")
	if err != nil {
		t.Errorf("Unexpected error with special character password: %v", err)
	}

	// Test with unicode characters
	_, err = auth.HashPassword("こんにちは世界")
	if err != nil {
		t.Errorf("Unexpected error with unicode password: %v", err)
	}
}

// TestComparePasswordsWithInvalidHash tests error cases in ComparePasswords
func TestComparePasswordsWithInvalidHash(t *testing.T) {
	// Test with invalid hash
	err := auth.ComparePasswords("not-a-valid-bcrypt-hash", "password")
	if err == nil {
		t.Errorf("Expected error with invalid hash, got nil")
	}

	// Test with empty hash
	err = auth.ComparePasswords("", "password")
	if err == nil {
		t.Errorf("Expected error with empty hash, got nil")
	}

	// Test with hash that's too short
	err = auth.ComparePasswords("$2a$10$", "password")
	if err == nil {
		t.Errorf("Expected error with short hash, got nil")
	}
}

// TestSignInWithCorruptedPassword tests sign in with a valid user but corrupted password hash
func TestSignInWithCorruptedPassword(t *testing.T) {
	// Create a custom mock store where we can corrupt the password hash
	store := NewMockStore()

	// Manually create a user with corrupted hash
	email := "user@example.com"
	corruptedHash := "$2a$10$corrupted-hash-that-wont-validate"
	userID := "user_" + email

	// Directly set up the corrupted data in the store
	store.users[email] = corruptedHash
	store.userIDs[email] = userID

	// Create the authenticator
	secret := "test-secret-key"
	authenticator := auth.New(secret, store)
	ctx := context.Background()

	// Try to sign in, which should fail due to hash comparison
	_, _, _, _, err := authenticator.SignIn(ctx, email, "password")
	if err == nil {
		t.Errorf("Expected error when password hash is corrupted, got nil")
	}
}
