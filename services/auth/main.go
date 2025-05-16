package main

import (
	"os"

	"github.com/charmbracelet/log"
	"github.com/vasapolrittideah/money-tracker-api/services/auth/server"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/logger"
	"github.com/vasapolrittideah/money-tracker-api/shared/validator"
)

func main() {
	logger.InitLogger(os.Stderr, log.DebugLevel)
	validator.InitValidator()

	cfg, err := config.LoadConfig()
	if err != nil {
		logger.Fatal("AUTH", "Failed to load configuration: %v", err)
	}

	httpServer := server.NewAuthHttpServer(cfg)
	httpServer.Run()
}
