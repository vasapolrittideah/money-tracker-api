package authtypes

import "github.com/golang-jwt/jwt/v5"

type Tokens struct {
	AccessToken  string
	RefreshToken string
}

type JWTClaims struct {
	jwt.RegisteredClaims

	UserID    string `json:"user_id"`
	SessionID string `json:"session_id"`
}

type OAuthUser struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

type FacebookUser struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email"`
}

type FacebookTokenResponse struct {
	Data struct {
		AppID       string `json:"app_id"`
		Application string `json:"application"`
		ExpiresAt   int64  `json:"expires_at"`
		IsValid     bool   `json:"is_valid"`
		UserID      string `json:"user_id"`
	} `json:"data"`
}

type AppleClaims struct {
	jwt.RegisteredClaims

	Issuer         string `json:"iss"`
	Audience       string `json:"aud"`
	ExpirationTime int64  `json:"exp"`
	IssuedAt       int64  `json:"iat"`
	Subject        string `json:"sub"`
	NonceSupported bool   `json:"nonce_supported,omitempty"`
	Nonce          string `json:"nonce,omitempty"`
	Email          string `json:"email,omitempty"`
	EmailVerified  string `json:"email_verified,omitempty"`
	IsPrivateEmail string `json:"is_private_email,omitempty"`
	RealUserStatus int    `json:"real_user_status,omitempty"`
	TransferSub    string `json:"transfer_sub,omitempty"`
}
