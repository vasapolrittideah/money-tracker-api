package domain

import (
	"context"
	"time"

	userv1 "github.com/vasapolrittideah/money-tracker-api/protogen/user/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type User struct {
	ID           uint64    `json:"id"         gorm:"primaryKey;autoIncrement"   example:"1"                    extensions:"x-order=1"`
	FullName     string    `json:"full_name"  gorm:"not null;type:varchar(100)" example:"John Doe"             extensions:"x-order=2"`
	Email        string    `json:"email"      gorm:"not null;uniqueIndex"       example:"john@example.com"     extensions:"x-order=3"`
	Verified     bool      `json:"verified"   gorm:"not null;default:false"     example:"true"                 extensions:"x-order=4"`
	Registered   bool      `json:"registered" gorm:"not null;default:false"     example:"true"                 extensions:"x-order=5"`
	Password     string    `json:"-"          gorm:"not null"`
	RefreshToken string    `json:"-"`
	CreatedAt    time.Time `json:"created_at" gorm:"autoCreateTime"             example:"2022-01-01T00:00:00Z" extensions:"x-order=6"`
	UpdatedAt    time.Time `json:"updated_at" gorm:"autoUpdateTime"             example:"2022-01-01T00:00:00Z" extensions:"x-order=7"`
}

func (u *User) ToProto() *userv1.User {
	return &userv1.User{
		Id:           u.ID,
		FullName:     u.FullName,
		Email:        u.Email,
		Verified:     u.Verified,
		Registered:   u.Registered,
		Password:     u.Password,
		RefreshToken: u.RefreshToken,
		CreatedAt:    timestamppb.New(u.CreatedAt),
		UpdatedAt:    timestamppb.New(u.UpdatedAt),
	}
}

func NewUserFromProto(user *userv1.User) *User {
	return &User{
		ID:           user.Id,
		FullName:     user.FullName,
		Email:        user.Email,
		Verified:     user.Verified,
		Registered:   user.Registered,
		Password:     user.Password,
		RefreshToken: user.RefreshToken,
		CreatedAt:    user.CreatedAt.AsTime(),
		UpdatedAt:    user.UpdatedAt.AsTime(),
	}
}

type UpdateUserRequest struct {
	FullName     *string `json:"full_name"     example:"John Doe"         extensions:"x-order=1"`
	Email        *string `json:"email"         example:"john@example.com" extensions:"x-order=2" validate:"omitempty,email"`
	Password     *string `json:"password"      example:"securepassword"   extensions:"x-order=3"`
	Verified     *bool   `json:"verified"      example:"true"             extensions:"x-order=4"`
	Registered   *bool   `json:"registered"    example:"true"             extensions:"x-order=5"`
	RefreshToken *string `json:"refresh_token" example:"refresh_token"    extensions:"x-order=6"`
}

type UserUsecase interface {
	GetAllUsers(ctx context.Context) ([]*User, error)
	GetUserByID(ctx context.Context, id uint64) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, user *User) (*User, error)
	UpdateUser(ctx context.Context, user *User) (*User, error)
	DeleteUser(ctx context.Context, id uint64) (*User, error)
}

type UserRepository interface {
	GetAllUsers(ctx context.Context) ([]*User, error)
	GetUserByID(ctx context.Context, id uint64) (*User, error)
	GetUserByEmail(ctx context.Context, email string) (*User, error)
	CreateUser(ctx context.Context, user *User) (*User, error)
	UpdateUser(ctx context.Context, user *User) (*User, error)
	DeleteUser(ctx context.Context, id uint64) (*User, error)
}
