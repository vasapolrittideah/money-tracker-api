package domain

import (
	"context"

	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

// AuthUsecase defines the interface for authentication-related use cases.
type AuthUsecase interface {
	Login(ctx context.Context, params LoginParams) (*authtypes.Tokens, error)
	SignUp(ctx context.Context, params SignUpParams) (*authtypes.Tokens, error)
	LoginWithGoogle(ctx context.Context, params LoginWithGoogleParams) (*authtypes.Tokens, error)
}

// LoginParams defines the parameters for user login.
type LoginParams struct {
	Email    string
	Password string
}

// SignUpParams defines the parameters for user sign-up.
type SignUpParams struct {
	Email    string
	Password string
	FullName string
}

// LoginWithGoogleParams defines the parameters for logging in with Google.
type LoginWithGoogleParams struct {
	IDToken string
}
