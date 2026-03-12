package repository

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/entity"
)

// AccountRepository defines persistence operations for Account entities.
type AccountRepository interface {
	// CreateAccount inserts a new Account into the database and returns the
	// created entity with its assigned ID.
	CreateAccount(ctx context.Context, account *entity.Account) (*entity.Account, error)

	// ListAccounts returns a list of Accounts matching the given filter parameters.
	ListAccounts(ctx context.Context, params *FilterAccountsParams) ([]*entity.Account, error)

	// GetAccountByID looks up an Account by its unique ID.
	GetAccountByID(ctx context.Context, id string) (*entity.Account, error)

	// GetAccountByEmail looks up an Account by its unique email address.
	GetAccountByEmail(ctx context.Context, email string) (*entity.Account, error)

	// UpdateAccount applies the non-nil fields in params to the Account with the given ID,
	// and returns the updated entity.
	UpdateAccount(ctx context.Context, id string, params *UpdateAccountParams) (*entity.Account, error)

	// DeleteAccount removes the Account with the given ID from the database
	// and returns the deleted entity.
	DeleteAccount(ctx context.Context, id string) (*entity.Account, error)
}

// UpdateAccountParams holds the optional fields that can be updated on an Account.
// Only non-nil fields are applied.
type UpdateAccountParams struct {
	Email          *string
	HashedPassword *string
	Verified       *bool
}

// FilterAccountsParams specifies filtering, pagination, and sorting options
// for ListAccounts queries.
type FilterAccountsParams struct {
	Email    *string
	Verified *bool
	Limit    uint64
	Offset   uint64
	SortBy   *string
	SortDesc bool
}
