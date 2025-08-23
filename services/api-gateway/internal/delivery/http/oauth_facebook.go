package http

import (
	"net/http"

	"github.com/vasapolrittideah/money-tracker-api/services/api-gateway/internal/payload"
	authpbv1 "github.com/vasapolrittideah/money-tracker-api/shared/protos/auth/v1"
	"github.com/vasapolrittideah/money-tracker-api/shared/utilities"
	"github.com/vasapolrittideah/money-tracker-api/shared/validator"
)

func (h *AuthHTTPHandler) loginWithFacebook(w http.ResponseWriter, r *http.Request) {
	var req payload.LoginWithFacebookRequest
	if err := utilities.ReadJSON(w, r, &req); err != nil {
		utilities.WriteRequestErrorResponse(w, r, err.Error(), h.logger)
		return
	}

	if errs := validator.ValidateStruct(req); errs != nil {
		utilities.WriteValidationErrorResponse(w, r, errs, h.logger)
		return
	}

	grpcResp, err := h.authServiceClient.Client.LoginWithFacebook(r.Context(), &authpbv1.LoginWithFacebookRequest{
		AccessToken: req.AccessToken,
	})
	if err != nil {
		utilities.WriteInternalErrorResponse(w, r, err, h.logger)
		return
	}

	payload := payload.LoginWithFacebookResponse{
		AccessToken:  grpcResp.AccessToken,
		RefreshToken: grpcResp.RefreshToken,
	}

	utilities.WriteSuccessResponse(w, r, payload, h.logger)
}
