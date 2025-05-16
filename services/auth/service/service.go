package service

import (
	"context"
	"fmt"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/protogen/users_proto"
	"github.com/vasapolrittideah/money-tracker-api/services/auth/models"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"github.com/vasapolrittideah/money-tracker-api/shared/logger"
	"github.com/vasapolrittideah/money-tracker-api/shared/mapper"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/jwt_util"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/password_util"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type AuthService interface {
	SignUp(models.SignUpRequest) (*models.SignUpResponse, *app_error.Error)
	SignIn(models.SignInRequest) (*models.SignInResponse, *app_error.Error)
}

type authService struct {
	userClient users_proto.UserServiceClient
	cfg        *config.Config
}

func NewAuthService(userClient users_proto.UserServiceClient, cfg *config.Config) AuthService {
	return &authService{
		userClient: userClient,
		cfg:        cfg,
	}
}

func (s *authService) SignUp(req models.SignUpRequest) (*models.SignUpResponse, *app_error.Error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	hashedPassword, err := password_util.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	newUser := domain.User{
		FullName:       req.FullName,
		Email:          req.Email,
		HashedPassword: hashedPassword,
	}

	res, grpcErr := s.userClient.CreateUser(ctx, &users_proto.CreateUserRequest{
		FullName:       newUser.FullName,
		Email:          newUser.Email,
		HashedPassword: newUser.HashedPassword,
	})
	if grpcErr != nil {
		st := status.Convert(grpcErr)
		logger.Error("AUTH", "%s", st.Err())
		return nil, app_error.New(st.Code(), st.Err())
	}

	return &models.SignUpResponse{
		User: mapper.MapUserProtoToEntity(res.User),
	}, nil
}

func (s *authService) SignIn(req models.SignInRequest) (*models.SignInResponse, *app_error.Error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	res, grpcErr := s.userClient.GetUserByEmail(ctx, &users_proto.GetUserByEmailRequest{
		Email: req.Email,
	})
	if grpcErr != nil {
		st := status.Convert(grpcErr)
		return nil, app_error.New(st.Code(), st.Err())
	}

	user := mapper.MapUserProtoToEntity(res.User)

	if ok, err := password_util.VerifyPassword(user.HashedPassword, req.Password); err != nil || !ok {
		return nil, app_error.New(codes.Unauthenticated, fmt.Errorf("password is incorrect"))
	}

	accessToken, err := jwt_util.GenerateJwt(
		s.cfg.Security.AccessTokenExpiresIn,
		s.cfg.Security.AccessTokenPrivateKey,
		user.Id,
	)
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("failed to generate access token: %v", err.Error()))
	}

	refreshToken, err := jwt_util.GenerateJwt(
		s.cfg.Security.RefreshTokenExpiresIn,
		s.cfg.Security.RefreshTokenPrivateKey,
		user.Id,
	)
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("failed to generate refresh token: %v", err.Error()))
	}

	hashedRefreshToken, err := jwt_util.HashRefreshToken(refreshToken)
	if err != nil {
		return nil, app_error.New(
			codes.Internal,
			fmt.Errorf("failed to hash newly generated refresh token: %v", err.Error()),
		)
	}

	if _, err = s.userClient.UpdateUser(ctx, &users_proto.UpdateUserRequest{
		User: &users_proto.User{
			HashedRefreshToken: hashedRefreshToken,
		},
	}); err != nil {
		st := status.Convert(err)
		return nil, app_error.New(st.Code(), st.Err())
	}

	jwtRes := &models.SignInResponse{
		Jwt: domain.Jwt{
			AccessToken:  accessToken,
			RefreshToken: refreshToken,
		},
	}

	return jwtRes, nil
}
