package usecase

import "context"

type EmailVerificationUseCase interface {
	SendValidationEmail(ctx context.Context, params *SendValidationEmailParams) error

	VerifyEmail(ctx context.Context, params *VerifyEmailParams) error
}

type SendValidationEmailParams struct {
	AccountID string `json:"account_id" validate:"required"`
}

type VerifyEmailParams struct {
	AccountID string `json:"account_id" validate:"required"`
	Code      string `json:"code" validate:"required"`
}
