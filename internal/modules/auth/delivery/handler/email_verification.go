package handler

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	apperr "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/middleware"
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
		logger.Log.Error().Err(err).Msg("failed to send verification email")

		if err == apperr.ErrAccountNotFound {
			contract.WriteNotFoundResponse(w, middleware.LocalizeError(r.Context(), err))
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
		contract.WriteBadRequestResponse(w, middleware.LocalizeError(r.Context(), apperr.ErrInvalidRequestPayload))
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, middleware.LocalizeError(r.Context(), apperr.ErrValidationFailed), errs)
		return
	}

	err := h.emailVerificationUC.VerifyEmail(r.Context(), &req)
	if err != nil {
		logger.Log.Error().Err(err).Msg("failed to verify email")

		switch err {
		case apperr.ErrEmailVerificationNotFound:
			contract.WriteNotFoundResponse(w, middleware.LocalizeError(r.Context(), err))
			return

		case apperr.ErrEmailVerificationCodeExpired, apperr.ErrEmailVerificationCodeUsed, apperr.ErrEmailVerificationCodeInvalid:
			contract.WriteBadRequestResponse(w, middleware.LocalizeError(r.Context(), err))
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
		contract.WriteBadRequestResponse(w, middleware.LocalizeError(r.Context(), apperr.ErrInvalidRequestPayload))
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		contract.WriteValidationErrorResponse(w, middleware.LocalizeError(r.Context(), apperr.ErrValidationFailed), errs)
		return
	}

	err := h.emailVerificationUC.ChangeEmail(r.Context(), &req)
	if err != nil {
		logger.Log.Error().Err(err).Msg("failed to change email")

		switch err {
		case apperr.ErrAccountNotFound:
			contract.WriteNotFoundResponse(w, middleware.LocalizeError(r.Context(), err))
			return

		case apperr.ErrEmailUnchanged:
			contract.WriteBadRequestResponse(w, middleware.LocalizeError(r.Context(), err))
			return

		default:
			contract.WriteInternalErrorResponse(w)
			return
		}
	}

	contract.WriteSuccessResponse(w, nil)
}
