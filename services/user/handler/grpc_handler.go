package handler

import (
	"context"

	"github.com/google/uuid"
	userpb "github.com/vasapolrittideah/money-tracker-api/protogen/user"
	"github.com/vasapolrittideah/money-tracker-api/services/user/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/mapper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type UserGrpcHandler struct {
	service service.UserService
	userpb.UnimplementedUserServiceServer
	cfg *config.Config
}

func NewUserGrpcHandler(grpc *grpc.Server, service service.UserService, cfg *config.Config) {
	handler := &UserGrpcHandler{
		service: service,
		cfg:     cfg,
	}

	userpb.RegisterUserServiceServer(grpc, handler)
}

func (h *UserGrpcHandler) GetAllUsers(
	c context.Context,
	req *userpb.GetAllUsersRequest,
) (*userpb.GetAllUsersResponse, error) {
	users, err := h.service.GetAllUsers()
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	var protoUsers []*userpb.User
	for _, user := range users {
		protoUsers = append(protoUsers, mapper.MapUserEntityToProto(*user))
	}

	res := &userpb.GetAllUsersResponse{
		Users: protoUsers,
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserById(
	c context.Context,
	req *userpb.GetUserByIdRequest,
) (*userpb.GetUserByIdResponse, error) {
	user, err := h.service.GetUserById(uuid.MustParse(req.UserId))
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &userpb.GetUserByIdResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserByEmail(
	c context.Context,
	req *userpb.GetUserByEmailRequest,
) (*userpb.GetUserByEmailResponse, error) {
	user, err := h.service.GetUserByEmail(req.Email)
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &userpb.GetUserByEmailResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) CreateUser(
	c context.Context,
	req *userpb.CreateUserRequest,
) (*userpb.CreateUserResponse, error) {
	user, err := h.service.CreateUser(domain.User{
		FullName:       req.FullName,
		Email:          req.Email,
		HashedPassword: req.HashedPassword,
	})
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &userpb.CreateUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) UpdateUser(
	c context.Context,
	req *userpb.UpdateUserRequest,
) (*userpb.UpdateUserResponse, error) {
	user, err := h.service.UpdateUser(domain.User{
		FullName: req.User.FullName,
		Email:    req.User.Email,
	})
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &userpb.UpdateUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) DeleteUser(
	c context.Context,
	req *userpb.DeleteUserRequest,
) (*userpb.DeleteUserResponse, error) {
	user, err := h.service.DeleteUser(uuid.MustParse(req.UserId))
	if err != nil {
		return nil, status.Errorf(err.Code, "%s", err.Error())
	}

	res := &userpb.DeleteUserResponse{
		User: mapper.MapUserEntityToProto(user),
	}
	return res, nil
}
