package repository

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
)

// PasswordResetRepository defines persistence operations for PasswordReset entities.
type PasswordResetRepository interface {
	// Create creates a new PasswordReset record for the given account and returns
	// the signed reset token string.
	Create(ctx context.Context, passwordReset *entity.PasswordReset) (string, error)

	// GetByJTI retrieves the PasswordReset record identified by the given JWT ID.
	GetByJTI(ctx context.Context, jti string) (*entity.PasswordReset, error)

	// MarkAsUsed sets the Used flag to true on the record with the given JWT ID,
	// preventing the reset token from being accepted again.
	MarkAsUsed(ctx context.Context, jti string) error

	// InvalidateAllForAccount marks all existing password reset records for the given
	// account as used. Call this before creating a new record to ensure only one
	// active reset token exists per account at a time.
	InvalidateAllForAccount(ctx context.Context, accountID string) error
}
