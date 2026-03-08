package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

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

	// jwtMaker := token.NewJWTMaker(cfg.JWT.Issuer, cfg.JWT.Issuer)

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	serverAddr := ":" + cfg.App.Port

	server := &http.Server{
		Addr:         serverAddr,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
		Handler:      r,
	}

	r.Route("/api/v1", func(r chi.Router) {

	})

	serverErrors := make(chan error, 1)

	go func() {
		logger.Logger.Info().Str("addr", serverAddr).Msg("starting HTTP server")
		serverErrors <- server.ListenAndServe()
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
