package handler

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/validator"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
)

type EmailVerificationHandler struct {
	emailVerificationUC usecase.EmailVerificationUseCase
}

func NewEmailVerificationHandler(
	emailVerificationUC usecase.EmailVerificationUseCase,
) *EmailVerificationHandler {
	return &EmailVerificationHandler{
		emailVerificationUC: emailVerificationUC,
	}
}

func (h *EmailVerificationHandler) SendValidationEmail(w http.ResponseWriter, r *http.Request) {
	var req usecase.SendValidationEmailParams
	if err := utils.ReadJSON(w, r, &req); err != nil {
		contract.WriteBadRequestResponse(w, "invalid request payload")
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, errs)
		return
	}

	err := h.emailVerificationUC.SendValidationEmail(r.Context(), &req)
	if err != nil {
		if err == auth.ErrAccountNotFound {
			contract.WriteNotFoundResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w, err.Error())
		return
	}

	contract.WriteSuccessResponse(w, nil)
}

func (h *EmailVerificationHandler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	var req usecase.VerifyEmailParams
	if err := utils.ReadJSON(w, r, &req); err != nil {
		contract.WriteBadRequestResponse(w, "invalid request payload")
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, errs)
		return
	}

	err := h.emailVerificationUC.VerifyEmail(r.Context(), &req)
	if err != nil {
		switch err {
		case auth.ErrEmailVerificationNotFound:
			contract.WriteNotFoundResponse(w, err.Error())
			return

		case auth.ErrEmailVerificationExpired, auth.ErrEmailVerificationUsed, auth.ErrEmailVerificationInvalid:
			contract.WriteBadRequestResponse(w, err.Error())
			return

		default:
			contract.WriteInternalErrorResponse(w, err.Error())
			return
		}
	}

	contract.WriteSuccessResponse(w, nil)
}
