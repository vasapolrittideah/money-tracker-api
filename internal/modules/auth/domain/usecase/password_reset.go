package usecase

import "context"

// PasswordResetUseCase defines the application-level operations for password reset.
type PasswordResetUseCase interface {
	// SendPasswordResetEmail generates a signed reset token, stores it, and sends
	// a password reset link to the account's email address.
	// Any previously active reset records for the account are invalidated first.
	SendPasswordResetEmail(ctx context.Context) error

	// ResetPassword validates the reset token identified by JTI and updates the
	// account's password to NewPassword. Returns an error if the token is invalid,
	// expired, or has already been used.
	ResetPassword(ctx context.Context, params *ResetPasswordParams) error

	// ValidateResetToken checks whether the reset token identified by JTI is still
	// valid (i.e. unused and not expired) without consuming it.
	ValidateResetToken(ctx context.Context, params *ValidateResetTokenParams) error
}

// ResetPasswordParams holds the parameters required to reset a password.
type ResetPasswordParams struct {
	JTI         string `json:"jti" validate:"required"`
	NewPassword string `json:"new_password" validate:"required"`
}

// ValidateResetTokenParams holds the parameters required to validate a reset token.
type ValidateResetTokenParams struct {
	JTI string `json:"jti" validate:"required"`
}
