package handler

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	apperr "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/validator"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
)

type AuthHandler struct {
	authUC usecase.AuthUseCase
}

func NewAuthHandler(
	authUC usecase.AuthUseCase,
) *AuthHandler {
	return &AuthHandler{
		authUC: authUC,
	}
}

func (h *AuthHandler) LoginWithEmail(w http.ResponseWriter, r *http.Request) {
	var req usecase.LoginWithEmailParams
	if err := utils.ReadJSON(w, r, &req); err != nil {
		contract.WriteBadRequestResponse(w, "invalid request payload")
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, errs)
		return
	}

	resp, err := h.authUC.LoginWithEmail(r.Context(), &req)
	if err != nil {
		logger.Log.Error().Err(err).Msg("failed to login with email")

		if err == apperr.ErrInvalidCredentials {
			contract.WriteUnauthorizedResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w)
		return
	}

	contract.WriteSuccessResponse(w, resp)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req usecase.RegisterParams
	if err := utils.ReadJSON(w, r, &req); err != nil {
		contract.WriteBadRequestResponse(w, "invalid request payload")
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, errs)
		return
	}

	resp, err := h.authUC.Register(r.Context(), &req)
	if err != nil {
		logger.Log.Error().Err(err).Msg("failed to register account")

		if err == apperr.ErrAccountAlreadyExists {
			contract.WriteConflictResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w)
		return
	}

	contract.WriteSuccessResponse(w, resp)
}
