package grpc

import (
	"context"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/vasapolrittideah/money-tracker-api/services/auth-service/internal/domain"
	"github.com/vasapolrittideah/money-tracker-api/services/auth-service/internal/usecase"
	authpbv1 "github.com/vasapolrittideah/money-tracker-api/shared/protos/auth/v1"
)

func (h *authGRPCHandler) LoginWithFacebook(
	ctx context.Context,
	req *authpbv1.LoginWithFacebookRequest,
) (*authpbv1.LoginWithFacebookResponse, error) {
	params := domain.LoginWithFacebookParams{
		AccessToken: req.GetAccessToken(),
	}

	tokens, err := h.authUsecase.LoginWithFacebook(ctx, params)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to login with Facebook")

		switch {
		case errors.Is(err, usecase.ErrInvalidFacebookToken):
			return nil, status.Errorf(codes.Unauthenticated, "invalid facebook token")

		case errors.Is(err, usecase.ErrFacebookTokenExpired):
			return nil, status.Errorf(codes.Unauthenticated, "facebook token expired")

		default:
			return nil, status.Errorf(codes.Internal, "something went wrong")
		}
	}

	return &authpbv1.LoginWithFacebookResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
