package config

import (
	"time"

	"github.com/caarlos0/env/v11"
	"github.com/rs/zerolog"
)

// AuthServiceConfig contains the configuration for the auth service.
type AuthServiceConfig struct {
	Environment     string `env:"ENVIRONMENT"`
	Name            string `env:"SERVICE_NAME"`
	Address         string `env:"SERVICE_ADDRESS"`
	RegisterAddress string `env:"SERVICE_REGISTER_ADDRESS"`
	Token           TokenConfig
	Google          OAuthGoogleConfig
	Facebook        OAuthFacebookConfig
	Apple           OAuthAppleConfig
}

// OAuthAppleConfig contains the configuration for Apple OAuth.
type OAuthAppleConfig struct {
	ClientID   string `env:"OAUTH_APPLE_CLIENT_ID"`
	TeamID     string `env:"OAUTH_APPLE_TEAM_ID"`
	KeyID      string `env:"OAUTH_APPLE_KEY_ID"`
	PrivateKey string `env:"OAUTH_APPLE_PRIVATE_KEY"`
}

// OAuthFacebookConfig contains the configuration for Facebook OAuth.
type OAuthFacebookConfig struct {
	AppID     string `env:"OAUTH_FACEBOOK_APP_ID"`
	AppSecret string `env:"OAUTH_FACEBOOK_APP_SECRET"`
}

// OAuthGoogleConfig contains the configuration for Google OAuth.
type OAuthGoogleConfig struct {
	ClientID     string `env:"OAUTH_GOOGLE_CLIENT_ID"`
	ClientSecret string `env:"OAUTH_GOOGLE_CLIENT_SECRET"`
}

// TokenConfig contains the configuration for JWT tokens.
type TokenConfig struct {
	AccessTokenSecret     string        `env:"ACCESS_TOKEN_SECRET"`
	RefreshTokenSecret    string        `env:"REFRESH_TOKEN_SECRET"`
	AccessTokenExpiresIn  time.Duration `env:"ACCESS_TOKEN_EXPIRES_IN"`
	RefreshTokenExpiresIn time.Duration `env:"REFRESH_TOKEN_EXPIRES_IN"`
	Issuer                string        `env:"TOKEN_ISSUER"`
}

// NewAuthServiceConfig creates a new AuthServiceConfig instance from environment variables.
func NewAuthServiceConfig(logger *zerolog.Logger) *AuthServiceConfig {
	cfg, err := env.ParseAs[AuthServiceConfig]()
	if err != nil {
		logger.Fatal().Err(err).Msg("failed to parse environment variables")
	}

	return &cfg
}
