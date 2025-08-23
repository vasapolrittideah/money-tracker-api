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
