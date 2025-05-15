package handler

import (
	"context"

	"github.com/google/uuid"
	proto "github.com/vasapolrittideah/money-tracker-api/protogen/users"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type UserGrpcHandler struct {
	service service.UserService
	proto.UnimplementedUserServiceServer
	cfg *config.Config
}

func NewUserGrpcHandler(grpc *grpc.Server, service service.UserService, cfg *config.Config) {
	handler := &UserGrpcHandler{
		service: service,
		cfg:     cfg,
	}

	proto.RegisterUserServiceServer(grpc, handler)
}

func (h *UserGrpcHandler) GetAllUsers(
	c context.Context,
	req *proto.GetAllUsersRequest,
) (*proto.GetAllUsersResponse, error) {
	users, err := h.service.GetAllUsers()
	if err != nil {
		return nil, err
	}

	var protoUsers []*proto.User
	for _, user := range users {
		protoUsers = append(protoUsers, mapUserEntityToProto(*user))
	}

	res := &proto.GetAllUsersResponse{
		Users: protoUsers,
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserByID(
	c context.Context,
	req *proto.GetUserByIDRequest,
) (*proto.GetUserByIDResponse, error) {
	user, err := h.service.GetUserByID(uuid.MustParse(req.UserID))
	if err != nil {
		return nil, err
	}

	res := &proto.GetUserByIDResponse{
		User: mapUserEntityToProto(user),
	}
	return res, nil
}

func (h *UserGrpcHandler) GetUserByEmail(
	c context.Context,
	req *proto.GetUserByEmailRequest,
) (*proto.GetUserByEmailResponse, error) {
	user, err := h.service.GetUserByEmail(req.Email)
	if err != nil {
		return nil, err
	}

	res := &proto.GetUserByEmailResponse{
		User: mapUserEntityToProto(user),
	}
	return res, nil
}

func mapUserEntityToProto(user domain.User) *proto.User {
	return &proto.User{
		Id:           uuid.UUID(user.ID).String(),
		FullName:     user.FullName,
		Email:        user.Email,
		CreatedAt:    timestamppb.New(user.CreatedAt),
		UpdatedAt:    timestamppb.New(user.UpdatedAt),
		LastSignInAt: timestamppb.New(user.LastSignInAt),
	}
}
