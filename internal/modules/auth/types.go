package auth

import "github.com/golang-jwt/jwt/v5"

// JWT holds the access and refresh token pair returned after a successful authentication.
type JWT struct {
	AccessToken  string
	RefreshToken string
}

// JWTClaims extends jwt.RegisteredClaims with application-specific fields.
// It is used as the claims payload for both access and refresh tokens.
type JWTClaims struct {
	jwt.RegisteredClaims

	// UserID identifies the authenticated user this token was issued for.
	UserID string `json:"user_id"`

	// SessionID ties the token to a specific session, allowing targeted revocation.
	SessionID string `json:"session_id"`
}
