package databaseutil

import (
	"errors"
	"fmt"
	"strings"

	"github.com/vasapolrittideah/money-tracker-api/shared/constants/error_code"
	"gorm.io/gorm"
)

func HandleGeneralDatabaseError(err error) error {
	return fmt.Errorf("%s: %s", error_code.DatabaseError, err.Error())
}

func HandleRecordNotFoundError(err error) error {
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return fmt.Errorf("%s: %s", error_code.NotFound, err.Error())
	}

	return HandleGeneralDatabaseError(err)
}

func HandleUnqueConstraintError(err error) error {
	if strings.Contains(err.Error(), "duplicate key") {
		return fmt.Errorf("%s: %s", error_code.Conflict, err.Error())
	}

	return HandleGeneralDatabaseError(err)
}
