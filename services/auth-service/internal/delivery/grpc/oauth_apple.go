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

func (h *authGRPCHandler) LoginWithApple(
	ctx context.Context,
	req *authpbv1.LoginWithAppleRequest,
) (*authpbv1.LoginWithAppleResponse, error) {
	params := domain.LoginWithAppleParams{
		IdentityToken:     req.GetIdentityToken(),
		AuthorizationCode: req.GetAuthorizationCode(),
	}

	tokens, err := h.authUsecase.LoginWithApple(ctx, params)
	if err != nil {
		h.logger.Error().Err(err).Msg("failed to login with apple")

		switch {
		case errors.Is(err, usecase.ErrInvalidAppleToken):
			return nil, status.Errorf(codes.Unauthenticated, "invalid apple token")

		case errors.Is(err, usecase.ErrAppleTokenExpired):
			return nil, status.Errorf(codes.Unauthenticated, "apple token expired")

		default:
			return nil, status.Errorf(codes.Internal, "something went wrong")
		}
	}

	return &authpbv1.LoginWithAppleResponse{
		AccessToken:  tokens.AccessToken,
		RefreshToken: tokens.RefreshToken,
	}, nil
}
