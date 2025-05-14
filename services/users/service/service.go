package service

import (
	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/services/users/repository"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
)

type UserService interface {
	GetAllUsers() ([]domain.User, error)
	GetUserByID(uuid.UUID) (domain.User, error)
	GetUserByEmail(string) (domain.User, error)
}

type userService struct {
	userRepo repository.UserRepository
	cfg      *config.Config
}

func NewUserService(userRepo repository.UserRepository, cfg *config.Config) UserService {
	return &userService{userRepo, cfg}
}

func (s *userService) GetAllUsers() ([]domain.User, error) {
	return s.userRepo.GetAllUsers()
}

func (s *userService) GetUserByID(id uuid.UUID) (domain.User, error) {
	return s.userRepo.GetUserByID(id)
}

func (s *userService) GetUserByEmail(email string) (domain.User, error) {
	return s.userRepo.GetUserByEmail(email)
}
