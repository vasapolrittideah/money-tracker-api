package handler

import (
	"context"

	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/protogen/users_proto"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/mapper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type UserGrpcHandler struct {
	service service.UserService
	users_proto.UnimplementedUserServiceServer
	cfg *config.Config
}

func NewUserGrpcHandler(grpc *grpc.Server, service service.UserService, cfg *config.Config) {
	handler := &UserGrpcHandler{
		service: service,
		cfg:     cfg,
	}

	users_proto.RegisterUserServiceServer(grpc, handler)
}

func (h *UserGrpcHandler) GetAllUsers(
	c context.Context,
	req *users_proto.GetAllUsersRequest,
) (*users_proto.GetAllUsersResponse, error) {
	users, err := h.service.GetAllUsers()
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	var protoUsers []*users_proto.User
	for _, user := range users {
		protoUsers = append(protoUsers, mapper.MapUserEntityToProto(*user))
	}

	res := &users_proto.GetAllUsersResponse{
		Users: protoUsers,
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserById(
	c context.Context,
	req *users_proto.GetUserByIdRequest,
) (*users_proto.GetUserByIdResponse, error) {
	user, err := h.service.GetUserById(uuid.MustParse(req.UserId))
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &users_proto.GetUserByIdResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserByEmail(
	c context.Context,
	req *users_proto.GetUserByEmailRequest,
) (*users_proto.GetUserByEmailResponse, error) {
	user, err := h.service.GetUserByEmail(req.Email)
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &users_proto.GetUserByEmailResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) CreateUser(
	c context.Context,
	req *users_proto.CreateUserRequest,
) (*users_proto.CreateUserResponse, error) {
	user, err := h.service.CreateUser(domain.User{
		FullName:       req.FullName,
		Email:          req.Email,
		HashedPassword: req.HashedPassword,
	})
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &users_proto.CreateUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) UpdateUser(
	c context.Context,
	req *users_proto.UpdateUserRequest,
) (*users_proto.UpdateUserResponse, error) {
	user, err := h.service.UpdateUser(domain.User{
		FullName: req.User.FullName,
		Email:    req.User.Email,
	})
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &users_proto.UpdateUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) DeleteUser(
	c context.Context,
	req *users_proto.DeleteUserRequest,
) (*users_proto.DeleteUserResponse, error) {
	user, err := h.service.DeleteUser(uuid.MustParse(req.UserId))
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &users_proto.DeleteUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}
