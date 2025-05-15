package server

import (
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	middlewareLogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/vasapolrittideah/money-tracker-api/services/users/handler"
	"github.com/vasapolrittideah/money-tracker-api/services/users/repository"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/logger"
	"gorm.io/gorm"
)

type userHttpServer struct {
	cfg *config.Config
	db  *gorm.DB
}

func NewUserHttpServer(cfg *config.Config, db *gorm.DB) *userHttpServer {
	return &userHttpServer{cfg: cfg, db: db}
}

func (s *userHttpServer) Run() {
	app := fiber.New()

	loggerConfig := middlewareLogger.Config{
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
		middlewareLogger.New(loggerConfig),
		cors.New(corsConfig),
	)

	app.Get("/health", func(ctx *fiber.Ctx) error {
		return ctx.Status(fiber.StatusOK).SendString("OK")
	})

	router := app.Group("/api")

	userService := service.NewUserService(repository.NewUserRepository(s.db), s.cfg)
	userHandler := handler.NewUserHttpHandler(userService, router, s.cfg)
	userHandler.RegisterRouter()

	go func() {
		if err := app.Listen(":" + s.cfg.Server.UserServerHttpPort); err != nil {
			logger.L.Fatalf("[USERS] Failed to serve HTTP server: %v", err)
		}
	}()

	logger.L.Infof("[USERS] 🚀 HTTP server started on port %v", s.cfg.Server.UserServerHttpPort)

	quit := make(chan os.Signal, 1)
	signal.Notify(
		quit,
		os.Interrupt,
		syscall.SIGINT,
		syscall.SIGTERM,
	)
	<-quit
}
