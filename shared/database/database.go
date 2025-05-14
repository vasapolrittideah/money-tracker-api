package database

import (
	"fmt"

	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

func ConnectPostgresDB(dbConfig *config.DatabaseConfig) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=disable TimeZone=Asia/Bangkok",
		dbConfig.DBHost,
		dbConfig.DBUser,
		dbConfig.DBPassword,
		dbConfig.DBName,
		dbConfig.DBPort,
	)

	return gorm.Open(postgres.Open(dsn), &gorm.Config{})
}

func MigratePostgresDB(db *gorm.DB, models []any) error {
	db.Exec("CREATE EXTENSION IF NOT EXISTS \"uuid-ossp\"")
	return db.AutoMigrate(models...)
}
