package repository

import (
	"context"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
)

// SessionRepository defines persistence operations for Session entities.
type SessionRepository interface {
	// CreateSession inserts a new Session into the database and returns the
	// created entity with its assigned ID.
	CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error)

	// GetSessionByAccountID looks up a Session by its associated Account ID.
	GetSessionByAccountID(ctx context.Context, accountID string) (*entity.Session, error)

	// UpdateJWT replaces the token pair and their expiry times on an existing session.
	UpdateJWT(ctx context.Context, id string, params *UpdateJWTParams) (*entity.Session, error)
}

// UpdateJWTParams holds the new token pair and expiry times.
type UpdateJWTParams struct {
	AccessToken        string    `bson:"access_token"`
	RefreshToken       string    `bson:"refresh_token"`
	AccessTokenExpiry  time.Time `bson:"access_token_expiry"`
	RefreshTokenExpiry time.Time `bson:"refresh_token_expiry"`
}
