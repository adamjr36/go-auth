package tests

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
)

// MockStore implements the auth.Store interface for testing
type MockStore struct {
	mutex         sync.Mutex
	users         map[string]string              // key -> hashedPassword
	userIDs       map[string]string              // key -> userID
	refreshTokens map[string]string              // refreshToken -> refreshToken
	userTokens    map[string]map[string]struct{} // userID -> set of refresh tokens
}

func NewMockStore() *MockStore {
	return &MockStore{
		users:         make(map[string]string),
		userIDs:       make(map[string]string),
		refreshTokens: make(map[string]string),
		userTokens:    make(map[string]map[string]struct{}),
	}
}

func (m *MockStore) CreateUser(ctx context.Context, key string, password string) (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if _, exists := m.users[key]; exists {
		return "", errors.New("user already exists")
	}

	userID := "user_" + key
	m.users[key] = password
	m.userIDs[key] = userID

	return userID, nil
}

func (m *MockStore) GetUserAuth(ctx context.Context, key string) (string, string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	password, exists := m.users[key]
	if !exists {
		return "", "", errors.New("user not found")
	}

	userID := m.userIDs[key]

	return userID, password, nil
}

func (m *MockStore) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	token, exists := m.refreshTokens[refreshToken]
	if !exists {
		return "", errors.New("refresh token not found")
	}

	return token, nil
}

func (m *MockStore) SetRefreshToken(ctx context.Context, userID string, refreshToken string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.refreshTokens[refreshToken] = refreshToken

	// Store multiple tokens per user
	if _, exists := m.userTokens[userID]; !exists {
		m.userTokens[userID] = make(map[string]struct{})
	}
	m.userTokens[userID][refreshToken] = struct{}{}

	return nil
}

func (m *MockStore) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	delete(m.refreshTokens, refreshToken)

	// Also remove from user tokens map
	for userID, tokens := range m.userTokens {
		if _, exists := tokens[refreshToken]; exists {
			delete(m.userTokens[userID], refreshToken)
		}
	}

	return nil
}

func (m *MockStore) RevokeAllRefreshTokens(ctx context.Context, userID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Find and delete all tokens for this user
	if tokens, exists := m.userTokens[userID]; exists {
		for token := range tokens {
			delete(m.refreshTokens, token)
		}
		delete(m.userTokens, userID)
	}

	return nil
}

func (m *MockStore) DeleteUser(ctx context.Context, userID string) error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

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
	if tokens, exists := m.userTokens[userID]; exists {
		for token := range tokens {
			delete(m.refreshTokens, token)
		}
		delete(m.userTokens, userID)
	}

	return nil
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
