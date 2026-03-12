package usecase

import (
	"context"
)

// AccountUseCase defines application-level operations for managing Account entities.
type AccountUseCase interface {
	// GetCurrentAccount retrieves the account of the currently authenticated user.
	//
	// The accountID is extracted from the JWT claims stored in ctx by the auth middleware.
	GetCurrentAccount(ctx context.Context) (*AccountResponse, error)

	// DeleteAccount permanently removes the account of the currently authenticated user
	// and returns the deleted entity.
	//
	// The accountID is extracted from the JWT claims stored in ctx by the auth middleware.
	DeleteAccount(ctx context.Context) (*AccountResponse, error)
}

// AccountResponse is the data transfer object returned by AccountUseCase methods.
type AccountResponse struct {
	ID       string `json:"id"`
	Email    string `json:"email"`
	Verified bool   `json:"verified"`
}
