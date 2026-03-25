package token

import "github.com/golang-jwt/jwt/v5"

// JWTClaims extends jwt.RegisteredClaims with application-specific fields.
// It is used as the claims payload for both access and refresh tokens.
type JWTClaims struct {
	jwt.RegisteredClaims

	// AccountID identifies the authenticated user this token was issued for.
	AccountID string `json:"account_id"`

	// SessionID ties the token to a specific session, allowing targeted revocation.
	SessionID string `json:"session_id"`
}

// JTIClaims extends jwt.RegisteredClaims with a JTI field for one-time tokens.
// It is used for tokens that must be invalidated after a single use, such as
// password reset tokens.
type JTIClaims struct {
	jwt.RegisteredClaims

	AccountID string `json:"account_id"`
	JTI       string `json:"jti"`
}
