package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/vasapolrittideah/money-tracker-api/services/users/models"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/constants/error_code"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
)

type UserHttpHandler struct {
	service service.UserService
	router  fiber.Router
	cfg     *config.Config
}

func NewUserHttpHandler(service service.UserService, router fiber.Router, cfg *config.Config) UserHttpHandler {
	return UserHttpHandler{service, router, cfg}
}

func (h UserHttpHandler) RegisterRouter() {
	router := h.router.Group("/users")

	router.Get("/", h.GetAllUsers)
	router.Get("/:id", h.GetUserById)
	router.Get("/email/:email", h.GetUserByEmail)
}

func (h UserHttpHandler) GetAllUsers(c *fiber.Ctx) error {
	users, err := h.service.GetAllUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			domain.ErrorResponse(error_code.InternalError),
		)
	}

	return c.Status(fiber.StatusOK).JSON(domain.SuccessResponse(users))
}

func (h UserHttpHandler) GetUserById(c *fiber.Ctx) error {
	payload := new(models.GetOrderByIdRequest)

	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			domain.ErrorResponse(error_code.InvalidRequest),
		)
	}

	user, err := h.service.GetUserById(payload.Id)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			domain.ErrorResponse(error_code.InternalError),
		)
	}

	return c.Status(fiber.StatusOK).JSON(domain.SuccessResponse(user))
}

func (h UserHttpHandler) GetUserByEmail(c *fiber.Ctx) error {
	payload := new(models.GetOrderByEmailRequest)

	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			domain.ErrorResponse(error_code.InvalidRequest),
		)
	}

	user, err := h.service.GetUserByEmail(payload.Email)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			domain.ErrorResponse(error_code.InternalError),
		)
	}

	return c.Status(fiber.StatusOK).JSON(domain.SuccessResponse(user))
}
