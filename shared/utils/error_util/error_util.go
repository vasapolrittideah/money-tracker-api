package error_util

import (
	"errors"
	"strings"

	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"google.golang.org/grpc/codes"
	"gorm.io/gorm"
)

func HandleUnknownDatabaseError(err error) error {
	return app_error.New(codes.Unknown, "unknown database error: %s", err.Error())
}

func HandleRecordNotFoundError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return app_error.New(codes.NotFound, "record not found: %s", err.Error())
	}

	return HandleUnknownDatabaseError(err)
}

func HandleUnqiueConstraintError(err error) error {
	if strings.Contains(err.Error(), "duplicate key") {
		return app_error.New(codes.AlreadyExists, "duplicate key: %s", err.Error())
	}

	return HandleUnknownDatabaseError(err)
}
