package repository

import (
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func setUpTestDB(t *testing.T) (*gorm.DB, sqlmock.Sqlmock, func()) {
	db, mock, err := sqlmock.New()
	assert.NoError(t, err)

	dialector := postgres.New(postgres.Config{
		Conn:       db,
		DriverName: "postgres",
	})

	gormDB, err := gorm.Open(dialector, &gorm.Config{})
	assert.NoError(t, err)

	cleanup := func() {
		db.Close()
	}

	return gormDB, mock, cleanup
}

func TestGetUserById(t *testing.T) {
	db, mock, cleanup := setUpTestDB(t)
	defer cleanup()

	id := uuid.New()
	user := domain.User{
		Id:       id,
		FullName: "John Doe",
		Email:    "john@example.com",
	}

	mock.ExpectQuery(`SELECT \* FROM "users" WHERE id = \$1 ORDER BY "users"\."id" LIMIT 1`).
		WithArgs(id).
		WillReturnRows(sqlmock.NewRows([]string{"id", "full_name", "email"}).
			AddRow(user.Id, user.FullName, user.Email))

	repo := NewUserRepository(db)
	result, err := repo.GetUserById(id)

	assert.Nil(t, err)
	assert.Equal(t, user.Id, result.Id)
	assert.Equal(t, user.FullName, result.FullName)
	assert.Equal(t, user.Email, result.Email)
}
