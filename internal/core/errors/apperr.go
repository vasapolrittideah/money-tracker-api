package apperr

import "errors"

var (
	ErrValidationFailed      = errors.New("ErrValidationFailed")
	ErrInvalidRequestPayload = errors.New("ErrInvalidRequestPayload")

	ErrUnauthenticated    = errors.New("ErrUnauthenticated")
	ErrInvalidCredentials = errors.New("ErrInvalidCredentials")

	ErrAccountNotFound      = errors.New("ErrAccountNotFound")
	ErrAccountAlreadyExists = errors.New("ErrAccountAlreadyExists")

	ErrEmailVerificationNotFound    = errors.New("ErrEmailVerificationNotFound")
	ErrEmailVerificationCodeExpired = errors.New("ErrEmailVerificationCodeExpired")
	ErrEmailVerificationCodeUsed    = errors.New("ErrEmailVerificationCodeUsed")
	ErrEmailVerificationCodeInvalid = errors.New("ErrEmailVerificationCodeInvalid")
	ErrEmailUnchanged               = errors.New("ErrEmailUnchanged")
)
