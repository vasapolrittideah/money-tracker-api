package usecase

import (
	"context"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/middleware"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/usecase"
)

type accountUseCase struct {
	accountRepo repository.AccountRepository
}

func NewAccountUseCase(accountRepo repository.AccountRepository) usecase.AccountUseCase {
	return &accountUseCase{
		accountRepo: accountRepo,
	}
}

// GetCurrentAccount implements [usecase.AccountUseCase].
func (u *accountUseCase) GetCurrentAccount(ctx context.Context) (*usecase.AccountResponse, error) {
	claims, ok := middleware.ClaimsFromContext(ctx)
	if !ok {
		return nil, errors.ErrUnauthenticated
	}

	account, err := u.accountRepo.GetAccountByID(ctx, claims.AccountID)
	if err != nil {
		return nil, err
	}

	return &usecase.AccountResponse{
		ID:       account.ID.Hex(),
		Email:    account.Email,
		Verified: account.Verified,
	}, nil
}

// DeleteAccount implements [usecase.AccountUseCase].
func (u *accountUseCase) DeleteAccount(ctx context.Context) (*usecase.AccountResponse, error) {
	claims, ok := middleware.ClaimsFromContext(ctx)
	if !ok {
		return nil, errors.ErrUnauthenticated
	}

	account, err := u.accountRepo.DeleteAccount(ctx, claims.AccountID)
	if err != nil {
		return nil, err
	}

	return &usecase.AccountResponse{
		ID:       account.ID.Hex(),
		Email:    account.Email,
		Verified: account.Verified,
	}, nil
}
