package domain

import (
	"context"

	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

// AuthUsecase defines the interface for authentication-related use cases.
type AuthUsecase interface {
	Login(ctx context.Context, params LoginParams) (*authtypes.AuthTokens, error)
	SignUp(ctx context.Context, params SignUpParams) (*authtypes.AuthTokens, error)
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
}
