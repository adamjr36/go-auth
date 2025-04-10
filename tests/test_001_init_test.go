package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamjr36/auth"
)

// MockStore implements the auth.Store interface for testing
type MockStore struct {
	users         map[string]string // key -> hashedPassword
	userIDs       map[string]string // key -> userID
	refreshTokens map[string]string // refreshToken -> refreshToken
	userTokens    map[string]string // userID -> refreshToken
}

func NewMockStore() *MockStore {
	return &MockStore{
		users:         make(map[string]string),
		userIDs:       make(map[string]string),
		refreshTokens: make(map[string]string),
		userTokens:    make(map[string]string),
	}
}

func (m *MockStore) CreateUser(ctx context.Context, key string, password string) (string, error) {
	if _, exists := m.users[key]; exists {
		return "", errors.New("user already exists")
	}

	userID := "user_" + key
	m.users[key] = password
	m.userIDs[key] = userID

	return userID, nil
}

func (m *MockStore) GetUserAuth(ctx context.Context, key string) (string, string, error) {
	password, exists := m.users[key]
	if !exists {
		return "", "", errors.New("user not found")
	}

	userID := m.userIDs[key]

	return userID, password, nil
}

func (m *MockStore) GetRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	token, exists := m.refreshTokens[refreshToken]
	if !exists {
		return "", errors.New("refresh token not found")
	}

	return token, nil
}

func (m *MockStore) SetRefreshToken(ctx context.Context, userID string, refreshToken string) error {
	m.refreshTokens[refreshToken] = refreshToken
	m.userTokens[userID] = refreshToken

	return nil
}

func (m *MockStore) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	delete(m.refreshTokens, refreshToken)

	return nil
}

func (m *MockStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	// Find and delete all tokens for this user
	if token, exists := m.userTokens[userID]; exists {
		delete(m.refreshTokens, token)
		delete(m.userTokens, userID)
	}

	return nil
}

func (m *MockStore) DeleteUser(ctx context.Context, userID string) error {
	// Find the key for this userID
	var keyToDelete string
	for key, id := range m.userIDs {
		if id == userID {
			keyToDelete = key
			break
		}
	}

	if keyToDelete != "" {
		delete(m.users, keyToDelete)
		delete(m.userIDs, keyToDelete)
	}

	// Also revoke all tokens
	return m.RevokeAllRefreshTokens(ctx, userID)
}

// TestInitialization tests the initialization of the auth module
func TestInitialization(t *testing.T) {
	// Create a new authenticator with default config
	store := NewMockStore()
	secret := "test-secret-key"

	authenticator := auth.New(secret, store)

	if authenticator == nil {
		t.Errorf("Failed to initialize authenticator with default config")
	}

	// Create a new authenticator with custom config
	customConfig := auth.TokenConfig{
		AccessTokenExpiry:  30 * time.Minute,
		RefreshTokenExpiry: 48 * time.Hour,
		Issuer:             "test-issuer",
	}

	customAuthenticator := auth.NewWithConfig(secret, store, customConfig)

	if customAuthenticator == nil {
		t.Errorf("Failed to initialize authenticator with custom config")
	}
}
