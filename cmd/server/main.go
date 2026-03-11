package main

import (
	"context"
	"os"
	"os/signal"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/database"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cfg, err := config.Load()

	logger.Init(cfg.IsDevelopment())
	if err != nil {
		logger.Logger.Fatal().Err(err).Msg("failed to load configuration")
	}

	mongo := database.NewMongoDB(&cfg.Database)
	if err := mongo.Connect(ctx); err != nil {
		logger.Logger.Fatal().Err(err).Msg("failed to connect to MongoDB")
	}
	defer func() {
		if err := mongo.Disconnect(ctx); err != nil {
			logger.Logger.Error().Err(err).Msg("failed to disconnect from MongoDB")
		}
	}()

	server := NewServer(ctx, cfg, mongo)

	serverErrors := make(chan error, 1)

	go func() {
		serverErrors <- server.Start()
	}()

	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, os.Interrupt)

	select {
	case err := <-serverErrors:
		logger.Logger.Fatal().Err(err).Msg("failed to start HTTP server")

	case sig := <-shutdown:
		logger.Logger.Info().Interface("signal", sig).Msg("shutting down HTTP server")

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Logger.Error().Err(err).Msg("failed to gracefully shutdown HTTP server")
		}
	}
}
