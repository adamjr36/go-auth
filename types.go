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
type Authenticator interface {
	ValidateToken(ctx context.Context, token string) (userId string, err error)
	RefreshToken(ctx context.Context, refreshToken string) (jwt string, newRefreshToken string, expiresAt int64, err error)

	SignUp(ctx context.Context, key string, password string) (userId string, err error)
	SignIn(ctx context.Context, key string, password string) (userId string, jwt string, refreshToken string, expiresAt int64, err error)
	SignOut(ctx context.Context, refreshToken string) error
	SignOutAll(ctx context.Context, userId string) error
	DeleteUser(ctx context.Context, userId string) error
}

// Store interface defines the contract for storage operations related to authentication
type Store interface {
	CreateUser(ctx context.Context, key string, password string) (userId string, err error)        // sign up
	GetUserAuth(ctx context.Context, key string) (userId string, hashedPassword string, err error) // sign in

	GetRefreshToken(ctx context.Context, refreshToken string) (storedRefreshToken string, err error) // for refresh token validation
	SetRefreshToken(ctx context.Context, userId string, refreshToken string) (err error)             // for refresh token creation/update
	RevokeRefreshToken(ctx context.Context, refreshToken string) (err error)                         // for refresh token revocation
	RevokeAllRefreshTokens(ctx context.Context, userId string) (err error)                           // for sign out
	DeleteUser(ctx context.Context, userId string) error                                             // for user deletion
}

type authenticator struct {
	secret string
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
