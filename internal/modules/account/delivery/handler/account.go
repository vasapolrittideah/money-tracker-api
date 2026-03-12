package handler

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/usecase"
)

type AccountHandler struct {
	accountUC usecase.AccountUseCase
}

func NewAccountHandler(accountUC usecase.AccountUseCase) *AccountHandler {
	return &AccountHandler{
		accountUC: accountUC,
	}
}

func (h *AccountHandler) GetCurrentAccount(w http.ResponseWriter, r *http.Request) {
	account, err := h.accountUC.GetCurrentAccount(r.Context())
	if err != nil {
		if err == errors.ErrUnauthenticated {
			contract.WriteUnauthorizedResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w)
		return
	}

	contract.WriteSuccessResponse(w, account)
}

func (h *AccountHandler) DeleteAccount(w http.ResponseWriter, r *http.Request) {
	account, err := h.accountUC.DeleteAccount(r.Context())
	if err != nil {
		if err == errors.ErrUnauthenticated {
			contract.WriteUnauthorizedResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w)
		return
	}

	contract.WriteSuccessResponse(w, account)
}
