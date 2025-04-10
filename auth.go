package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// New creates a new Authenticator with the given secret key and store
func New(secret string, store Store) Authenticator {
	return &authenticator{
		secret: secret,
		store:  store,
		config: DefaultTokenConfig(),
	}
}

// NewWithConfig creates a new Authenticator with custom token configuration
func NewWithConfig(secret string, store Store, config TokenConfig) Authenticator {
	return &authenticator{
		secret: secret,
		store:  store,
		config: config,
	}
}

// ValidateToken validates a JWT token and returns the user ID if valid
func (a *authenticator) ValidateToken(ctx context.Context, tokenString string) (string, error) {
	// Parse the token with claims
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the signing algorithm
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(a.secret), nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrExpiredToken
		}
		return "", ErrInvalidToken
	}

	// Validate claims
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		// Check if the claims have a non-empty UserID
		if claims.UserID == "" {
			return "", ErrInvalidToken
		}
		return claims.UserID, nil
	}

	return "", ErrInvalidToken
}

// RefreshToken refreshes a JWT token using a valid refresh token
func (a *authenticator) RefreshToken(ctx context.Context, refreshToken string) (string, string, int64, error) {
	// Parse the token to get the user ID
	token, err := jwt.ParseWithClaims(refreshToken, &Claims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, ErrInvalidToken
		}
		return []byte(a.secret), nil
	})

	if err != nil {
		fmt.Println("Error parsing refresh token:", err)
		return "", "", 0, ErrRefreshToken
	}

	// Validate claims
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		fmt.Println("Invalid refresh token claims")
		return "", "", 0, ErrRefreshToken
	}

	// Get stored refresh token to verify it hasn't been revoked
	storedRefreshToken, err := a.store.GetRefreshToken(ctx, refreshToken)
	if err != nil || storedRefreshToken != refreshToken {
		fmt.Println("Invalid stored refresh token")
		return "", "", 0, ErrRefreshToken
	}

	// Generate new tokens
	jwt, newRefreshToken, expiresAt, err := a.generateTokens(claims.UserID)
	if err != nil {
		fmt.Println("Error generating tokens:", err)
		return "", "", 0, err
	}

	// Store the new refresh token
	if err := a.store.SetRefreshToken(ctx, claims.UserID, newRefreshToken); err != nil {
		fmt.Println("Error setting refresh token:", err)
		return "", "", 0, err
	}

	return jwt, newRefreshToken, expiresAt, nil
}

// SignUp creates a new user with the given key and password
func (a *authenticator) SignUp(ctx context.Context, key string, password string) (string, error) {
	// Hash the password before storing
	hashedPassword, err := HashPassword(password)
	if err != nil {
		return "", err
	}

	// Create the user in the store
	userId, err := a.store.CreateUser(ctx, key, hashedPassword)
	if err != nil {
		return "", err
	}

	return userId, nil
}

// SignIn authenticates a user and returns tokens if successful
func (a *authenticator) SignIn(ctx context.Context, key string, password string) (string, string, string, int64, error) {
	// Get user auth info from the store
	userId, hashedPassword, err := a.store.GetUserAuth(ctx, key)
	if err != nil {
		return "", "", "", 0, ErrInvalidCredentials
	}

	// Compare passwords
	err = ComparePasswords(hashedPassword, password)
	if err != nil {
		return "", "", "", 0, ErrInvalidCredentials
	}

	// Generate tokens
	jwt, refreshToken, expiresAt, err := a.generateTokens(userId)
	if err != nil {
		return "", "", "", 0, err
	}

	// Store the refresh token
	if err := a.store.SetRefreshToken(ctx, userId, refreshToken); err != nil {
		return "", "", "", 0, err
	}

	return userId, jwt, refreshToken, expiresAt, nil
}

// generateTokens creates a new JWT and refresh token pair, and returns the JWT, refresh token, and expiration time
func (a *authenticator) generateTokens(userId string) (string, string, int64, error) {
	expiresAt := time.Now().Add(a.config.AccessTokenExpiry)
	// Create access token
	accessClaims := Claims{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    a.config.Issuer,
			Subject:   userId,
		},
	}

	// Create the JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, accessClaims)
	tokenString, err := token.SignedString([]byte(a.secret))
	if err != nil {
		return "", "", 0, ErrTokenGeneration
	}

	// Create refresh token with longer expiry
	refreshClaims := Claims{
		UserID: userId,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(a.config.RefreshTokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    a.config.Issuer,
			Subject:   userId,
		},
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodHS256, refreshClaims)
	refreshTokenString, err := refreshToken.SignedString([]byte(a.secret))
	if err != nil {
		return "", "", 0, ErrTokenGeneration
	}

	return tokenString, refreshTokenString, expiresAt.Unix(), nil
}

// GenerateSecureToken generates a secure random token for refresh tokens
func GenerateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// SignOut revokes a user's refresh token
func (a *authenticator) SignOut(ctx context.Context, refreshToken string) error {
	return a.store.RevokeRefreshToken(ctx, refreshToken)
}

func (a *authenticator) SignOutAll(ctx context.Context, userId string) error {
	return a.store.RevokeAllRefreshTokens(ctx, userId)
}

// DeleteUser deletes a user from the store
func (a *authenticator) DeleteUser(ctx context.Context, userId string) error {
	return a.store.DeleteUser(ctx, userId)
}
