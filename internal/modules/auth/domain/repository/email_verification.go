package repository

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type EmailVerificationRepository interface {
	Create(ctx context.Context, verification *entity.EmailVerification) (*entity.EmailVerification, error)

	GetByAccountID(ctx context.Context, accountID string) (*entity.EmailVerification, error)

	MarkAsUsed(ctx context.Context, id bson.ObjectID) error

	InvalidateAllForAccount(ctx context.Context, accountID string) error
}
