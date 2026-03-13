package main

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/database"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/hash"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/mailer"
	app_middleware "github.com/vasapolrittideah/money-tracker-api/internal/core/middleware"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/token"
	account_delivery "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/delivery"
	account_handler "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/delivery/handler"
	account_repo "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/repository"
	account_usecase "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/usecase"
	auth_delivery "github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery"
	auth_handler "github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery/handler"
	auth_repo "github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/repository"
	auth_usecase "github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/usecase"
	"golang.org/x/crypto/bcrypt"
)

// Server holds the HTTP server and its configuration.
type Server struct {
	config     *config.Config
	httpServer *http.Server
}

// NewServer wires all dependencies — repositories, use cases, handlers, and routes —
// and returns a Server ready to start. It is the single place where the application's
// dependency graph is assembled. To add a new module, wire it here.
func NewServer(ctx context.Context, cfg *config.Config, db *database.MongoDB) *Server {
	jwtMaker := token.NewJWTMaker(cfg.JWT.Issuer, cfg.JWT.Issuer)
	bcryptHasher := hash.NewBcryptHasher(bcrypt.DefaultCost)
	cryptoHasher := hash.NewSHA256Hasher()
	m := mailer.NewMailer(&cfg.SMTP)

	accountRepo := account_repo.NewAccountRepository(ctx, db.GetDatabase())
	identityRepo := auth_repo.NewIdentityRepository(db.GetDatabase())
	sessionRepo := auth_repo.NewSessionRepository(db.GetDatabase())
	emailVerificationRepo := auth_repo.NewEmailVerificationRepository(ctx, db.GetDatabase())

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	authHandler := auth_handler.NewAuthHandler(
		auth_usecase.NewAuthUseCase(
			accountRepo,
			identityRepo,
			sessionRepo,
			db,
			jwtMaker,
			bcryptHasher,
			cryptoHasher,
			cfg,
		),
	)
	emailVerificationHandler := auth_handler.NewEmailVerificationHandler(
		auth_usecase.NewEmailVerificationUseCase(
			accountRepo,
			emailVerificationRepo,
			db,
			cryptoHasher,
			m,
		),
	)
	accountHandler := account_handler.NewAccountHandler(
		account_usecase.NewAccountUseCase(accountRepo),
	)

	authMiddleware := app_middleware.RequireAuth(jwtMaker, cfg.JWT.AccessSecretKey)

	r.Route("/api/v1", func(r chi.Router) {
		auth_delivery.RegisterRoutes(r, authHandler, emailVerificationHandler, authMiddleware)
		account_delivery.RegisterRoutes(r, accountHandler, authMiddleware)
	})

	httpServer := &http.Server{
		Addr:         ":" + cfg.App.Port,
		WriteTimeout: 30 * time.Second,
		ReadTimeout:  30 * time.Second,
		Handler:      r,
	}

	return &Server{config: cfg, httpServer: httpServer}
}

// Start begins accepting HTTP connections. It blocks until the server stops.
func (s *Server) Start() error {
	logger.Log.Info().Str("addr", s.httpServer.Addr).Msg("starting HTTP server")
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully drains active connections and stops the server.
// The provided context sets the deadline for the drain to complete.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}
