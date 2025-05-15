package app_error

import (
	"fmt"

	"google.golang.org/grpc/codes"
)

type AppError struct {
	Code    codes.Code
	Message string
}

func (e *AppError) Error() string {
	return fmt.Sprintf("[%s]: %s", e.Code.String(), e.Message)
}

func New(code codes.Code, format string, args ...any) *AppError {
	return &AppError{
		Code:    code,
		Message: fmt.Sprintf(format, args...),
	}
}

func Assert(err error) *AppError {
	if appErr, ok := err.(*AppError); ok {
		return appErr
	}

	return New(codes.Unknown, "%s", err.Error())
}
