package auth

import "errors"

var (
	ErrAccountAlreadyExists = errors.New("account with the given email already exists")
	ErrInvalidCredentials   = errors.New("invalid email or password")
)
