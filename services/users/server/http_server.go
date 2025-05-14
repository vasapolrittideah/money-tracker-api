package server

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/charmbracelet/log"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/vasapolrittideah/money-tracker-api/services/users/handler"
	"github.com/vasapolrittideah/money-tracker-api/services/users/repository"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/database"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"gorm.io/gorm"
)

var DB *gorm.DB

type httpServer struct {
	cfg *config.Config
}

func NewHttpServer() *httpServer {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	db, err := database.ConnectPostgresDB(&cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}

	DB = db
	log.Info("🎉 Connected to database successfully")

	entities := []any{
		&domain.User{},
	}
	if err := database.MigratePostgresDB(DB, entities); err != nil {
		log.Fatalf("Failed to migrate database: %v", err)
	}

	return &httpServer{cfg: cfg}
}

func (s *httpServer) Run() {
	app := fiber.New()

	loggerConfig := logger.Config{
		TimeFormat: time.RFC1123Z,
		TimeZone:   "Asia/Bangkok",
	}

	corsConfig := cors.Config{
		AllowOrigins: "*",
		AllowHeaders: "Origin, Content-Type, Accept",
		AllowMethods: strings.Join([]string{
			fiber.MethodGet,
			fiber.MethodPost,
			fiber.MethodPut,
			fiber.MethodDelete,
		}, ","),
	}

	app.Use(
		recover.New(),
		logger.New(loggerConfig),
		cors.New(corsConfig),
	)

	app.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).SendString("OK")
	})

	router := app.Group("/api")

	authService := service.NewUserService(repository.NewUserRepository(DB), s.cfg)
	handler.RegisterAuthHttpHandler(router, s.cfg, authService)

	go func() {
		if err := app.Listen(":" + s.cfg.Server.AuthServerHttpPort); err != nil {
			log.Fatalf("Failed to listen and serve application: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(
		quit,
		os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	<-quit
}
