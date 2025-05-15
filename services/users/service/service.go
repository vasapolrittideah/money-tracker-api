package service

import (
	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/services/users/repository"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
)

type UserService interface {
	GetAllUsers() ([]*domain.User, error)
	GetUserById(uuid.UUID) (domain.User, error)
	GetUserByEmail(string) (domain.User, error)
	CreateUser(domain.User) (domain.User, error)
	UpdateUser(domain.User) (domain.User, error)
	DeleteUser(uuid.UUID) (domain.User, error)
}

type userService struct {
	userRepo repository.UserRepository
	cfg      *config.Config
}

func NewUserService(userRepo repository.UserRepository, cfg *config.Config) UserService {
	return &userService{userRepo, cfg}
}

func (s *userService) GetAllUsers() ([]*domain.User, error) {
	return s.userRepo.GetAllUsers()
}

func (s *userService) GetUserById(id uuid.UUID) (domain.User, error) {
	return s.userRepo.GetUserById(id)
}

func (s *userService) GetUserByEmail(email string) (domain.User, error) {
	return s.userRepo.GetUserByEmail(email)
}

func (s *userService) CreateUser(user domain.User) (domain.User, error) {
	return s.userRepo.CreateUser(user)
}

func (s *userService) UpdateUser(user domain.User) (domain.User, error) {
	return s.userRepo.UpdateUser(user)
}

func (s *userService) DeleteUser(id uuid.UUID) (domain.User, error) {
	return s.userRepo.DeleteUser(id)
}
