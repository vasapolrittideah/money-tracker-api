package error_util

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"google.golang.org/grpc/codes"
	"gorm.io/gorm"
)

func HandleUnknownDatabaseError(err error) *app_error.Error {
	return app_error.New(codes.Unknown, fmt.Errorf("unknown database error: %s", err))
}

func HandleRecordNotFoundError(err error) *app_error.Error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return app_error.New(codes.NotFound, fmt.Errorf("record not found: %s", err))
	}

	return HandleUnknownDatabaseError(err)
}

func HandleUnqiueConstraintError(err error) *app_error.Error {
	if strings.Contains(err.Error(), "duplicate key") {
		return app_error.New(codes.AlreadyExists, fmt.Errorf("duplicate key: %s", err))
	}

	return HandleUnknownDatabaseError(err)
}
