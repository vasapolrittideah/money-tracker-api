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

func (h *authGRPCHandler) LoginWithGoogle(
	ctx context.Context,
	req *authpbv1.LoginWithGoogleRequest,
) (*authpbv1.LoginWithGoogleResponse, error) {
	params := domain.LoginWithGoogleParams{
		IDToken: req.GetIdToken(),
	}

	tokens, err := h.authUsecase.LoginWithGoogle(ctx, params)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to login with google")

		switch {
		case errors.Is(err, usecase.ErrInvalidGoogleAudience):
			return nil, status.Errorf(codes.Unauthenticated, "invalid google audience")

		default:
			return nil, status.Errorf(codes.Internal, "something went wrong")
		}
	}

	return &authpbv1.LoginWithGoogleResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
