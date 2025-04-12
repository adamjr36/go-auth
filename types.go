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
// "key" is provided as a variable name to allow for flexibility in the implementation (email, username, etc.)
// "id" is the unique identifier form the store. It can be the key, a user id, session id, etc.
//   - "id" is the value stored in the token claims (TODO: make configurable)
type Authenticator interface {
	// ValidateToken validates a JWT token and returns the ID in the token if valid
	ValidateToken(ctx context.Context, token string) (id string, err error)

	// RefreshToken refreshes a refreshToken and returns the new JWT token, new refresh token, and the expiration time
	// of the newRefreshToken
	RefreshToken(ctx context.Context, refreshToken string) (jwt string, newRefreshToken string, expiresAt int64, err error)

	// SignUp creates a new user and returns the user ID
	SignUp(ctx context.Context, key string, password string) (id string, err error)

	// SignIn authenticates a user and returns the id, JWT token, refresh token, and the expiration time
	SignIn(ctx context.Context, key string, password string) (id string, jwt string, refreshToken string, expiresAt int64, err error)

	// SignOut revokes a refresh token
	SignOut(ctx context.Context, refreshToken string) error

	// SignOutAll revokes all refresh tokens for a user
	SignOutAll(ctx context.Context, id string) error

	// DeleteUser deletes a user. It only calls the store's DeleteUser method
	// But that method should revoke all refresh tokens for the user first
	DeleteUser(ctx context.Context, id string) error
}

// Store interface defines the contract for storage operations related to authentication
// It should be implemented by the user and passed to the authenticator
// "key" is provided as a variable name to allow for flexibility in the implementation (email, username, etc.)
// "id" is the unique identifier form the store. It can be the key, a user id, session id, etc.
//   - "id" is the value stored in the token claims (TODO: make configurable)
type Store interface {
	// CreateUser creates a new user and returns a user id associated with this key (can be the key).
	// It should store the key and hashedPassword in the store
	CreateUser(ctx context.Context, key string, hashedPassword string) (userId string, err error) // sign up

	// GetUserAuth returns the id and hashedPassword for a given key from the store
	// If ID is tied to the user (username, email, user id, etc.) then it should return the id for the given key from the store
	// If ID is tied to the session (session id, etc.) then it should generate a new id to return (e.g. random uuid).
	//    - The ID will be used to generate the claims in a token that will immediately be used in a call to SetRefreshToken(id, refreshToken)
	//      where the store can then create a record with that session id and refresh token.
	GetUserAuth(ctx context.Context, key string) (id string, hashedPassword string, err error) // sign in

	// ValidateRefreshToken returns the stored refresh token for a given refresh token from the store
	// Really just a dummy function to confirm that the refresh token is stored in the store
	ValidateRefreshToken(ctx context.Context, refreshToken string) (storedRefreshToken string, err error) // for refresh token validation

	// SetRefreshToken stores the refresh token for a given id in the store
	// Up to the user to overwrite previous refresh tokens for the user or not
	//    - allow for multiple sessions per user or not
	SetRefreshToken(ctx context.Context, id string, refreshToken string) (err error) // for refresh token creation/update

	// RevokeRefreshToken revokes a refresh token in the store
	RevokeRefreshToken(ctx context.Context, refreshToken string) (err error) // for refresh token revocation

	// RevokeAllRefreshTokens revokes all refresh tokens for a id from the store
	RevokeAllRefreshTokens(ctx context.Context, id string) (err error) // for sign out

	// DeleteUser deletes a user from the store.
	// It should revoke all refresh tokens for the user
	DeleteUser(ctx context.Context, id string) error // for user deletion
}

type authenticator struct {
	secret string // secret key for signing and verifying tokens
	store  Store
	config TokenConfig
}

// Claims represents the custom JWT claims structure
type Claims struct {
	ID string `json:"id"`
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
