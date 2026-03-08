package repository

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
)

// IdentityRepository defines persistence operations for Identity entities.
type IdentityRepository interface {
	CreateIdentity(ctx context.Context, identity *entity.Identity) (*entity.Identity, error)

	// ListIdentitiesByAccountID returns all OAuth identities linked to the given account.
	ListIdentitiesByAccountID(ctx context.Context, accountID string) ([]*entity.Identity, error)

	// GetIdentityByProvider looks up an identity by its provider name and provider-issued user ID.
	GetIdentityByProvider(ctx context.Context, provider string, providerID string) (*entity.Identity, error)

	// UpdateLastLogin records the current time as the last login timestamp for the given account.
	UpdateLastLogin(ctx context.Context, accountID string) error
}
