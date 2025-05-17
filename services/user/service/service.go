package service

import (
	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/services/user/repository"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
)

type UserService interface {
	GetAllUsers() ([]*domain.User, *app_error.Error)
	GetUserById(uuid.UUID) (domain.User, *app_error.Error)
	GetUserByEmail(string) (domain.User, *app_error.Error)
	CreateUser(domain.User) (domain.User, *app_error.Error)
	UpdateUser(domain.User) (domain.User, *app_error.Error)
	DeleteUser(uuid.UUID) (domain.User, *app_error.Error)
}

type userService struct {
	userRepo repository.UserRepository
	cfg      *config.Config
}

func NewUserService(userRepo repository.UserRepository, cfg *config.Config) UserService {
	return &userService{userRepo, cfg}
}

func (s *userService) GetAllUsers() ([]*domain.User, *app_error.Error) {
	return s.userRepo.GetAllUsers()
}

func (s *userService) GetUserById(id uuid.UUID) (domain.User, *app_error.Error) {
	return s.userRepo.GetUserById(id)
}

func (s *userService) GetUserByEmail(email string) (domain.User, *app_error.Error) {
	return s.userRepo.GetUserByEmail(email)
}

func (s *userService) CreateUser(user domain.User) (domain.User, *app_error.Error) {
	return s.userRepo.CreateUser(user)
}

func (s *userService) UpdateUser(user domain.User) (domain.User, *app_error.Error) {
	return s.userRepo.UpdateUser(user)
}

func (s *userService) DeleteUser(id uuid.UUID) (domain.User, *app_error.Error) {
	return s.userRepo.DeleteUser(id)
}
