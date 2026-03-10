package repository

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// EmailVerificationRepository defines persistence operations for EmailVerification entities.
type EmailVerificationRepository interface {
	// Create inserts a new EmailVerification record into the database and returns
	// the created entity with its assigned ID.
	Create(ctx context.Context, verification *entity.EmailVerification) (*entity.EmailVerification, error)

	// GetByAccountID returns the most recent unused, unexpired verification record
	// for the given account, or an error if none exists.
	GetByAccountID(ctx context.Context, accountID string) (*entity.EmailVerification, error)

	// MarkAsUsed sets the Used flag to true on the record with the given ID,
	// preventing it from being accepted again.
	MarkAsUsed(ctx context.Context, id bson.ObjectID) error

	// InvalidateAllForAccount marks all existing verification records for the given
	// account as used. Call this before creating a new record to ensure only one
	// active verification exists per account at a time.
	InvalidateAllForAccount(ctx context.Context, accountID string) error
}
