package http

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/services/api-gateway/internal/payload"
	authpbv1 "github.com/vasapolrittideah/money-tracker-api/shared/protos/auth/v1"
	"github.com/vasapolrittideah/money-tracker-api/shared/utilities"
	"github.com/vasapolrittideah/money-tracker-api/shared/validator"
)

func (h *AuthHTTPHandler) loginWithApple(w http.ResponseWriter, r *http.Request) {
	var req payload.LoginWithAppleRequest
	if err := utilities.ReadJSON(w, r, &req); err != nil {
		utilities.WriteRequestErrorResponse(w, r, err.Error(), h.logger)
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		utilities.WriteValidationErrorResponse(w, r, errs, h.logger)
		return
	}

	grpcResp, err := h.authServiceClient.Client.LoginWithApple(r.Context(), &authpbv1.LoginWithAppleRequest{
		IdentityToken:     req.IdentityToken,
		AuthorizationCode: req.AuthorizationCode,
	})
	if err != nil {
		utilities.WriteInternalErrorResponse(w, r, err, h.logger)
		return
	}

	payload := payload.LoginWithAppleResponse{
		AccessToken:  grpcResp.AccessToken,
		RefreshToken: grpcResp.RefreshToken,
	}

	utilities.WriteSuccessResponse(w, r, payload, h.logger)
}
