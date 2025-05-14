package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
)

func RegisterAuthHttpHandler(r fiber.Router, cfg *config.Config, service service.UserService) {
	h := NewAuthHttpHandler(service, cfg)
	router := r.Group("/users")

	router.Get("/", h.GetAllUsers)
	router.Get("/:id", h.GetUserByID)
	router.Get("/email/:email", h.GetUserByEmail)
}
