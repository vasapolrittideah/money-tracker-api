package domain

import (
	"context"

	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

// AuthUsecase defines the interface for authentication-related use cases.
type AuthUsecase interface {
	Login(ctx context.Context, params LoginParams) (*authtypes.AuthTokens, error)
	Register(ctx context.Context, params RegisterParams) (*authtypes.AuthTokens, error)
}

// LoginParams defines the parameters for user login.
type LoginParams struct {
	Email    string
	Password string
}

// RegisterParams defines the parameters for user registration.
type RegisterParams struct {
	Email    string
	Password string
}
