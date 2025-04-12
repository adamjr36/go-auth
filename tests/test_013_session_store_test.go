package tests

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/adamjr36/go-auth"
	"github.com/google/uuid"
)

// SessionStore implements the auth.Store interface with session-based IDs
type SessionStore struct {
	users    map[string]string   // key -> hashedPassword
	sessions map[string]*Session // sessionID -> Session
}

type Session struct {
	Key          string
	RefreshToken string
	IsRevoked    bool
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		users:    make(map[string]string),
		sessions: make(map[string]*Session),
	}
}

func (s *SessionStore) CreateUser(ctx context.Context, key string, hashedPassword string) (string, error) {
	if _, exists := s.users[key]; exists {
		return "", errors.New("user already exists")
	}

	s.users[key] = hashedPassword
	return key, nil
}

func (s *SessionStore) GetUserAuth(ctx context.Context, key string) (string, string, error) {
	hashedPassword, exists := s.users[key]
	if !exists {
		return "", "", errors.New("user not found")
	}

	// Generate a new session ID for each authentication
	sessionID := uuid.New().String()
	s.sessions[sessionID] = &Session{
		Key:       key,
		IsRevoked: false,
	}

	return sessionID, hashedPassword, nil
}

func (s *SessionStore) ValidateRefreshToken(ctx context.Context, refreshToken string) (string, error) {
	for _, session := range s.sessions {
		if session.RefreshToken == refreshToken && !session.IsRevoked {
			return refreshToken, nil
		}
	}
	return "", errors.New("refresh token not found")
}

func (s *SessionStore) SetRefreshToken(ctx context.Context, sessionID string, refreshToken string) error {
	session, exists := s.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	// Create a new session with the updated refresh token
	// Always set IsRevoked to false for new refresh tokens
	updatedSession := &Session{
		Key:          session.Key,
		RefreshToken: refreshToken,
		IsRevoked:    false,
	}

	// Store the updated session
	s.sessions[sessionID] = updatedSession
	return nil
}

func (s *SessionStore) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	var sessionIDToRevoke string

	// Find the session with the matching refresh token
	for id, sess := range s.sessions {
		if sess.RefreshToken == refreshToken {
			sessionIDToRevoke = id
			break
		}
	}

	if sessionIDToRevoke == "" {
		return errors.New("refresh token not found")
	}

	// Only revoke the specific session that matches the refresh token
	session := s.sessions[sessionIDToRevoke]

	// Create a new session with IsRevoked set to true
	updatedSession := &Session{
		Key:          session.Key,
		RefreshToken: session.RefreshToken,
		IsRevoked:    true,
	}

	// Store the updated session
	s.sessions[sessionIDToRevoke] = updatedSession
	return nil
}

func (s *SessionStore) RevokeAllRefreshTokens(ctx context.Context, sessionID string) error {
	session, exists := s.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	// Create a new session with IsRevoked set to true
	updatedSession := &Session{
		Key:          session.Key,
		RefreshToken: session.RefreshToken,
		IsRevoked:    true,
	}

	// Store the updated session
	s.sessions[sessionID] = updatedSession
	return nil
}

func (s *SessionStore) DeleteUser(ctx context.Context, sessionID string) error {
	session, exists := s.sessions[sessionID]
	if !exists {
		return errors.New("session not found")
	}

	// Delete all sessions for this user
	for id, sess := range s.sessions {
		if sess.Key == session.Key {
			delete(s.sessions, id)
		}
	}

	// Delete the user
	delete(s.users, session.Key)
	return nil
}

// TestSessionStore tests the session-based store implementation
func TestSessionStore(t *testing.T) {
	store := NewSessionStore()
	secret := "test-secret-key"
	auth := auth.New(secret, store)

	// Test user creation
	userID, err := auth.SignUp(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to create user: %v", err)
	}
	if userID != "test@example.com" {
		t.Errorf("Expected userID to be the key, got %s", userID)
	}

	// Test authentication with session ID generation
	sessionID, jwt, refreshToken, expiresAt, err := auth.SignIn(context.Background(), "test@example.com", "password123")
	if err != nil {
		t.Fatalf("Failed to sign in: %v", err)
	}

	// Verify session ID is a valid UUID
	_, err = uuid.Parse(sessionID)
	if err != nil {
		t.Errorf("Session ID is not a valid UUID: %v", err)
	}

	// Verify token validation works with session ID
	validatedID, err := auth.ValidateToken(context.Background(), jwt)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if validatedID != sessionID {
		t.Errorf("Expected validated ID to match session ID, got %s", validatedID)
	}

	time.Sleep(1 * time.Second)

	// Test token refresh
	newJWT, newRefreshToken, newExpiresAt, err := auth.RefreshToken(context.Background(), refreshToken)
	if err != nil {
		t.Fatalf("Failed to refresh token: %v", err)
	}

	// Verify new token contains same session ID
	newValidatedID, err := auth.ValidateToken(context.Background(), newJWT)
	if err != nil {
		t.Fatalf("Failed to validate new token: %v", err)
	}
	if newValidatedID != sessionID {
		t.Errorf("Expected new validated ID to match original session ID, got %s", newValidatedID)
	}

	// Verify expiration times are different
	if expiresAt == newExpiresAt {
		t.Error("Expected new token to have different expiration time")
	}

	// Test sign out
	err = auth.SignOut(context.Background(), newRefreshToken)
	if err != nil {
		t.Fatalf("Failed to sign out: %v", err)
	}

	// Verify refresh token is revoked
	_, _, _, err = auth.RefreshToken(context.Background(), newRefreshToken)
	if err == nil {
		t.Error("Expected error when using revoked refresh token")
	}
}
