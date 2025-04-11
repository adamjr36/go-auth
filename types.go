package auth

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Common errors
var (
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrInvalidToken       = errors.New("invalid token")
	ErrExpiredToken       = errors.New("token expired")
	ErrTokenGeneration    = errors.New("failed to generate token")
	ErrRefreshToken       = errors.New("invalid refresh token")
)

// Authenticator interface defines the contract for authentication operations
// It relies on a user provided store to manage user data, like storing user credentials and refresh tokens
type Authenticator interface {
	// ValidateToken validates a JWT token and returns the user ID in the token if valid
	ValidateToken(ctx context.Context, token string) (userId string, err error)

	// RefreshToken refreshes a refreshToken and returns the new JWT token, new refresh token, and the expiration time
	// of the newRefreshToken
	RefreshToken(ctx context.Context, refreshToken string) (jwt string, newRefreshToken string, expiresAt int64, err error)

	// SignUp creates a new user and returns the user ID
	SignUp(ctx context.Context, key string, password string) (userId string, err error)

	// SignIn authenticates a user and returns the user ID, JWT token, refresh token, and the expiration time
	SignIn(ctx context.Context, key string, password string) (userId string, jwt string, refreshToken string, expiresAt int64, err error)

	// SignOut revokes a refresh token
	SignOut(ctx context.Context, refreshToken string) error

	// SignOutAll revokes all refresh tokens for a user
	SignOutAll(ctx context.Context, userId string) error

	// DeleteUser deletes a user. It only calls the store's DeleteUser method
	// But that method should revoke all refresh tokens for the user first
	DeleteUser(ctx context.Context, userId string) error
}

// Store interface defines the contract for storage operations related to authentication
// It should be implemented by the user and passed to the authenticator
// "key" is provided as a variable name to allow for flexibility in the implementation (email, username, etc.)
// "userId" is the unique identifier for the user in the store. It COULD be the same as "key" but doesn't have to be
type Store interface {
	// CreateUser creates a new user and returns the user ID associated with this key.
	// It should store the key and hashedPassword in the store
	CreateUser(ctx context.Context, key string, hashedPassword string) (userId string, err error) // sign up

	// GetUserAuth returns the user ID and hashedPassword for a given key from the store
	GetUserAuth(ctx context.Context, key string) (userId string, hashedPassword string, err error) // sign in

	// GetRefreshToken returns the stored refresh token for a given refresh token from the store
	// Really just a dummy function to confirm that the refresh token is stored in the store
	GetRefreshToken(ctx context.Context, refreshToken string) (storedRefreshToken string, err error) // for refresh token validation

	// SetRefreshToken stores the refresh token for a given user ID in the store
	// Up to the user to overwrite previous refresh tokens for the user or not
	//    - allow for multiple sessions per user or not
	SetRefreshToken(ctx context.Context, userId string, refreshToken string) (err error) // for refresh token creation/update

	// RevokeRefreshToken revokes a refresh token in the store
	RevokeRefreshToken(ctx context.Context, refreshToken string) (err error) // for refresh token revocation

	// RevokeAllRefreshTokens revokes all refresh tokens for a user from the store
	RevokeAllRefreshTokens(ctx context.Context, userId string) (err error) // for sign out

	// DeleteUser deletes a user from the store.
	// It should revoke all refresh tokens for the user
	DeleteUser(ctx context.Context, userId string) error // for user deletion
}

type authenticator struct {
	secret string // secret key for signing and verifying tokens
	store  Store
	config TokenConfig
}

// Claims represents the custom JWT claims structure
type Claims struct {
	UserID string `json:"userId"`
	jwt.RegisteredClaims
}

// TokenPair represents a JWT access token and refresh token pair
type TokenPair struct {
	JWT          string `json:"jwt"`
	RefreshToken string `json:"refreshToken"`
}

// TokenConfig holds configuration for token generation
type TokenConfig struct {
	AccessTokenExpiry  time.Duration
	RefreshTokenExpiry time.Duration
	Issuer             string
}

// DefaultTokenConfig returns a default token configuration
func DefaultTokenConfig() TokenConfig {
	return TokenConfig{
		AccessTokenExpiry:  15 * time.Minute,   // 15 minutes
		RefreshTokenExpiry: 7 * 24 * time.Hour, // 7 days
		Issuer:             "auth.service",
	}
}
