package main

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/vasapolrittideah/money-tracker-api/services/user/server"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/database"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/logger"
	"github.com/vasapolrittideah/money-tracker-api/shared/validator"
)

func main() {
	logger.InitLogger(os.Stderr, log.DebugLevel)
	validator.InitValidator()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("USERS", "Failed to load configuration: %v", err)
	}

	db, err := database.ConnectPostgresDB(&cfg.Database)
	if err != nil {
		logger.Fatal("USERS", "Failed to connect to database: %v", err)
	}

	logger.Info("USERS", "🎉 Connected to database successfully")

	entities := []any{
		&domain.User{},
	}
	if err := database.MigratePostgresDB(db, entities); err != nil {
		logger.Fatal("USERS", "Failed to migrate database: %v", err)
	}

	httpServer := server.NewUserHttpServer(cfg, db)
	go httpServer.Run()

	grpcServer := server.NewUserGrpcServer(cfg, db)
	grpcServer.Run()
}
