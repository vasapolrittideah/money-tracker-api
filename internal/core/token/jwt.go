package token

import (
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims extends jwt.RegisteredClaims with application-specific fields.
// It is used as the claims payload for both access and refresh tokens.
type JWTClaims struct {
	jwt.RegisteredClaims

	// AccountID identifies the authenticated user this token was issued for.
	AccountID string `json:"account_id"`

	// SessionID ties the token to a specific session, allowing targeted revocation.
	SessionID string `json:"session_id"`
}

// JWTMaker handles JWT generation and validation.
// Every token it produces is scoped to a specific audience and issuer,
// which are verified during validation to prevent token reuse across services.
type JWTMaker struct {
	audience string
	issuer   string
}

// NewJWTMaker returns a new JWTMaker that stamps and verifies the given
// audience and issuer claims on every token.
func NewJWTMaker(audience, issuer string) *JWTMaker {
	return &JWTMaker{
		audience: audience,
		issuer:   issuer,
	}
}

// GenerateToken signs the given claims with the provided secret using HMAC-SHA256
// and returns the compact token string.
func (m *JWTMaker) GenerateToken(claims jwt.Claims, secret string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenStr, err := token.SignedString([]byte(secret))
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

// ValidateToken parses and validates the given token string against the provided secret.
// It enforces HMAC-SHA256 signing, expiration, audience, and issuer claims.
// Returns the parsed *jwt.Token on success, or an error if any check fails.
func (m *JWTMaker) ValidateToken(tokenStr, secret string) (*jwt.Token, error) {
	return jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte(secret), nil
	},
		jwt.WithExpirationRequired(),
		jwt.WithAudience(m.audience),
		jwt.WithIssuer(m.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)
}

// ValidateTokenWithClaims is like ValidateToken but unmarshals the token payload
// into the provided claims value. Use this when you need to access custom claim fields
// after validation. Returns an error if the token is invalid or the claims cannot be mapped.
func (m *JWTMaker) ValidateTokenWithClaims(tokenString, secret string, claims jwt.Claims) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		return []byte(secret), nil
	},
		jwt.WithExpirationRequired(),
		jwt.WithAudience(m.audience),
		jwt.WithIssuer(m.issuer),
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Name}),
	)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	return token, nil
}
