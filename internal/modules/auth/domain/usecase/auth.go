package usecase

import "context"

// AuthUseCase defines the application-level operations for authentication.
type AuthUseCase interface {
	// LoginWithEmail authenticates a user with email and password.
	// Returns the access token and refresh token on success.
	LoginWithEmail(ctx context.Context, params *LoginWithEmailParams) (string, string, error)

	// Register creates a new account with the given email and password.
	// Returns the access token and refresh token for the newly created session.
	Register(ctx context.Context, params *RegisterParams) (string, string, error)
}

// LoginWithEmailParams holds the credentials required for email/password login.
type LoginWithEmailParams struct {
	Email    string
	Password string
}

// RegisterParams holds the credentials required to create a new account.
type RegisterParams struct {
	Email    string
	Password string
}
