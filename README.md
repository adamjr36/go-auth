# Auth Package

A secure JWT-based authentication and authorization package for Go applications. This package is a wrapper around jwt and bcrypt for standard authentication boilerplate for a typical backend API. The authenticator interface can easily be used to verify jwt in middleware, as well as handle the heavy lifting in signup, signin, ... authentication routes (provided with a store interface by the user.)

Note: Tests and Documentation mostly written with AI. Well tested with these tests and others, as well as in a larger API application.

## Features

- Secure JWT token generation and validation
- Refresh token management for token renewal
- User signup and signin functionality
- Password hashing with bcrypt
- Modular design with clean interfaces
- Some customization with token expiries configurable

## Usage

### Initialize the Authenticator

```go
// Create a store implementation that satisfies the auth.Store interface
type MyStore struct {
    // implementation details
}

// Create a new authenticator with a secure secret key
secret := "your-strong-secret-key" // in production use env variables
store := &MyStore{}
authenticator := auth.New(secret, store)

// Alternatively, use custom token configuration
config := auth.TokenConfig{
    AccessTokenExpiry:  30 * time.Minute,
    RefreshTokenExpiry: 14 * 24 * time.Hour,
    Issuer:             "my-service",
}
authenticator := auth.NewWithConfig(secret, store, config)
```

### User Registration

```go
// Sign up a new user
userId, err := authenticator.SignUp("user@example.com", "password123")
if err != nil {
    // Handle error
}
```

### User Authentication

```go
// Sign in a user
userId, jwtToken, refreshToken, err := authenticator.SignIn("user@example.com", "password123")
if err != nil {
    // Handle error
}

// Use jwt token for authorization
```

### Token Validation

```go
// Validate a JWT token
userId, err := authenticator.ValidateToken(jwtToken)
if err != nil {
    // Handle token error
    if errors.Is(err, auth.ErrExpiredToken) {
        // Handle expired token
    }
}
```

### Token Refresh

```go
// Refresh an expired token
newJwt, newRefreshToken, expiresAt, err := authenticator.RefreshToken(refreshToken)
if err != nil {
    // Handle refresh error
}

// Use the new tokens
```

## Security Considerations

1. **Secret Key**: Use a strong, randomly generated secret key and store it securely (e.g., environment variables, secret manager)
2. **Token Expiry**: Keep access tokens short-lived (15-30 minutes)
3. **HTTPS**: Always transmit tokens over HTTPS
4. **Cookie Storage**: Store tokens in HttpOnly and Secure cookies when possible
5. **Token Revocation**: Implement a strategy for revoking tokens when needed

## Implementation Notes

The package implements token issuing and validation following JWT best practices:
- HMAC SHA-256 for token signing
- Standard JWT claims including expiration, issuing time, and issuer
- Token refresh with rotation and validation

## License

[MIT](LICENSE) 