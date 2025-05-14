package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/vasapolrittideah/money-tracker-api/services/users/models"
	"github.com/vasapolrittideah/money-tracker-api/services/users/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/constants/error_code"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
)

type AuthHttpHandler struct {
	service service.UserService
	cfg     *config.Config
}

func NewAuthHttpHandler(service service.UserService, cfg *config.Config) AuthHttpHandler {
	return AuthHttpHandler{service, cfg}
}

func (h AuthHttpHandler) GetAllUsers(c *fiber.Ctx) error {
	users, err := h.service.GetAllUsers()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			domain.ErrorResponse(error_code.InternalError),
		)
	}

	return c.Status(fiber.StatusOK).JSON(domain.SuccessResponse(users))
}

func (h AuthHttpHandler) GetUserByID(c *fiber.Ctx) error {
	payload := new(models.GetOrderByIDRequest)

	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			domain.ErrorResponse(error_code.InvalidRequest),
		)
	}

	user, err := h.service.GetUserByID(payload.ID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			domain.ErrorResponse(error_code.InternalError),
		)
	}

	return c.Status(fiber.StatusOK).JSON(domain.SuccessResponse(user))
}

func (h AuthHttpHandler) GetUserByEmail(c *fiber.Ctx) error {
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
