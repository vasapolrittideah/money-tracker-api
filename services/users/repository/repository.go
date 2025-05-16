package repository

import (
	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/error_util"
	"gorm.io/gorm"
)

type UserRepository interface {
	GetAllUsers() ([]*domain.User, *app_error.Error)
	GetUserById(uuid.UUID) (domain.User, *app_error.Error)
	GetUserByEmail(string) (domain.User, *app_error.Error)
	CreateUser(domain.User) (domain.User, *app_error.Error)
	UpdateUser(domain.User) (domain.User, *app_error.Error)
	DeleteUser(uuid.UUID) (domain.User, *app_error.Error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return userRepository{db}
}

func (r userRepository) GetAllUsers() ([]*domain.User, *app_error.Error) {
	var users []*domain.User
	if err := r.db.Find(&users).Error; err != nil {
		return nil, error_util.HandleRecordNotFoundError(err)
	}

	return users, nil
}

func (r userRepository) GetUserById(id uuid.UUID) (domain.User, *app_error.Error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		return user, error_util.HandleRecordNotFoundError(err)
	}

	return user, nil
}

func (r userRepository) GetUserByEmail(email string) (domain.User, *app_error.Error) {
	var user domain.User
	if err := r.db.First(&user, "email = ?", email).Error; err != nil {
		return user, error_util.HandleRecordNotFoundError(err)
	}

	return user, nil
}

func (r userRepository) CreateUser(user domain.User) (domain.User, *app_error.Error) {
	if err := r.db.Create(&user).Error; err != nil {
		return user, error_util.HandleUnqiueConstraintError(err)
	}

	return user, nil
}

func (r userRepository) UpdateUser(newUserData domain.User) (domain.User, *app_error.Error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", newUserData.Id).Error; err != nil {
		return user, error_util.HandleRecordNotFoundError(err)
	}

	if err := r.db.Model(&user).Updates(newUserData.Id).Error; err != nil {
		return user, error_util.HandleUnknownDatabaseError(err)
	}

	return user, nil
}

func (r userRepository) DeleteUser(id uuid.UUID) (domain.User, *app_error.Error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		return user, error_util.HandleRecordNotFoundError(err)
	}

	if err := r.db.Delete(&user).Error; err != nil {
		return user, error_util.HandleUnknownDatabaseError(err)
	}

	return user, nil
}
