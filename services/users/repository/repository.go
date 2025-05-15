package repository

import (
	"fmt"

	"github.com/google/uuid"
	"github.com/vasapolrittideah/money-tracker-api/shared/constants/error_code"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/databaseutil"
	"gorm.io/gorm"
)

type UserRepository interface {
	GetAllUsers() ([]*domain.User, error)
	GetUserByID(uuid.UUID) (domain.User, error)
	GetUserByEmail(string) (domain.User, error)
	CreateUser(domain.User) (domain.User, error)
	UpdateUser(uuid.UUID, domain.User) (domain.User, error)
	DeleteUser(uuid.UUID) (domain.User, error)
}

type userRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) UserRepository {
	return userRepository{db}
}

func (r userRepository) GetAllUsers() ([]*domain.User, error) {
	var users []*domain.User
	if err := r.db.Find(&users).Error; err != nil {
		return nil, fmt.Errorf("%s: %s", error_code.DatabaseError, err.Error())
	}

	return users, nil
}

func (r userRepository) GetUserByID(id uuid.UUID) (domain.User, error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		return user, databaseutil.HandleRecordNotFoundError(err)
	}

	return user, nil
}

func (r userRepository) GetUserByEmail(email string) (domain.User, error) {
	var user domain.User
	if err := r.db.First(&user, "email = ?", email).Error; err != nil {
		return user, databaseutil.HandleRecordNotFoundError(err)
	}

	return user, nil
}

func (r userRepository) CreateUser(user domain.User) (domain.User, error) {
	if err := r.db.Create(&user).Error; err != nil {
		return user, databaseutil.HandleUnqueConstraintError(err)
	}

	return user, nil
}

func (r userRepository) UpdateUser(id uuid.UUID, newData domain.User) (domain.User, error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		return user, databaseutil.HandleRecordNotFoundError(err)
	}

	if err := r.db.Model(&user).Updates(newData).Error; err != nil {
		return user, databaseutil.HandleGeneralDatabaseError(err)
	}

	return user, nil
}

func (r userRepository) DeleteUser(id uuid.UUID) (domain.User, error) {
	var user domain.User
	if err := r.db.First(&user, "id = ?", id).Error; err != nil {
		return user, databaseutil.HandleRecordNotFoundError(err)
	}

	if err := r.db.Delete(&user).Error; err != nil {
		return user, databaseutil.HandleGeneralDatabaseError(err)
	}

	return user, nil
}
