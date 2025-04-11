package auth

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a bcrypt hash from a plain text password
// TODO: Make this configurable
func HashPassword(password string) (string, error) {
	// bcrypt has a limit of 72 bytes
	if len(password) > 71 {
		return "", errors.New("password length exceeds maximum limit of 71 characters")
	}

	// Use bcrypt with a cost of 10 (can be adjusted based on your security needs)
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ComparePasswords compares a hashed password with a plain text password
func ComparePasswords(hashedPassword, plainPassword string) error {
	if len(plainPassword) > 71 {
		return errors.New("password length exceeds maximum limit of 71 characters")
	}
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
}
