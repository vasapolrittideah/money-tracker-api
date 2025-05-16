package mapper

import (
	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/protogen/users_proto"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func MapUserEntityToProto(user domain.User) *users_proto.User {
	return &users_proto.User{
		Id:             uuid.UUID(user.Id).String(),
		FullName:       user.FullName,
		Email:          user.Email,
		HashedPassword: user.HashedPassword,
		Verified:       user.Verified,
		CreatedAt:      timestamppb.New(user.CreatedAt),
		UpdatedAt:      timestamppb.New(user.UpdatedAt),
		LastSignInAt:   timestamppb.New(user.LastSignInAt),
	}
}

func MapUserProtoToEntity(user *users_proto.User) domain.User {
	return domain.User{
		Id:             uuid.MustParse(user.Id),
		FullName:       user.FullName,
		Email:          user.Email,
		HashedPassword: user.HashedPassword,
		Verified:       user.Verified,
		CreatedAt:      user.CreatedAt.AsTime(),
		UpdatedAt:      user.UpdatedAt.AsTime(),
		LastSignInAt:   user.LastSignInAt.AsTime(),
	}
}
