package handler

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	apperr "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/validator"
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

func (h *EmailVerificationHandler) SendVerificationEmail(w http.ResponseWriter, r *http.Request) {
	err := h.emailVerificationUC.SendVerificationEmail(r.Context())
	if err != nil {
		if err == apperr.ErrAccountNotFound {
			contract.WriteNotFoundResponse(w, err.Error())
			return
		}

		contract.WriteInternalErrorResponse(w)
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
		case apperr.ErrEmailVerificationNotFound:
			contract.WriteNotFoundResponse(w, err.Error())
			return

		case apperr.ErrEmailVerificationExpired, apperr.ErrEmailVerificationUsed, apperr.ErrEmailVerificationInvalid:
			contract.WriteBadRequestResponse(w, err.Error())
			return

		default:
			contract.WriteInternalErrorResponse(w)
			return
		}
	}

	contract.WriteSuccessResponse(w, nil)
}

func (h *EmailVerificationHandler) ChangeEmail(w http.ResponseWriter, r *http.Request) {
	var req usecase.ChangeEmailParams
	if err := utils.ReadJSON(w, r, &req); err != nil {
		contract.WriteBadRequestResponse(w, "invalid request payload")
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, errs)
		return
	}

	err := h.emailVerificationUC.ChangeEmail(r.Context(), &req)
	if err != nil {
		switch err {
		case apperr.ErrAccountNotFound:
			contract.WriteNotFoundResponse(w, err.Error())
			return

		case apperr.ErrEmailUnchanged:
			contract.WriteBadRequestResponse(w, err.Error())
			return

		default:
			contract.WriteInternalErrorResponse(w)
			return
		}
	}

	contract.WriteSuccessResponse(w, nil)
}
