package usecase

import "context"

// EmailVerificationUseCase defines the application-level operations for email verification.
type EmailVerificationUseCase interface {
	// SendVerificationEmail generates a one-time verification code, stores its hash,
	// and sends the plain-text code to the account's email address.
	// Any previously active verification records for the account are invalidated first.
	SendVerificationEmail(ctx context.Context) error

	// VerifyEmail validates the submitted code against the stored hash and marks
	// the account as verified. Returns an error if the code is incorrect, expired,
	// or has already been used.
	VerifyEmail(ctx context.Context, params *VerifyEmailParams) error

	// ChangeEmail changes the email address associated with the account and initiates
	// a new verification process. It invalidates any existing verification records
	// and sends a new code to the new email address.
	ChangeEmail(ctx context.Context, params *ChangeEmailParams) error
}

// VerifyEmailParams holds the parameters required to verify an email address.
type VerifyEmailParams struct {
	Code string `json:"code" validate:"required"`
}

type ChangeEmailParams struct {
	OldEmail string `json:"old_email" validate:"required,email"`
	NewEmail string `json:"new_email" validate:"required,email"`
}
