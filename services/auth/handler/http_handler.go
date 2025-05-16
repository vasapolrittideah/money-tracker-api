package handler

import (
	"github.com/gofiber/fiber/v2"
	"github.com/vasapolrittideah/money-tracker-api/services/auth/models"
	"github.com/vasapolrittideah/money-tracker-api/services/auth/service"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/response"
	"github.com/vasapolrittideah/money-tracker-api/shared/validator"
	"google.golang.org/grpc/codes"
)

type AuthHttpHandler struct {
	service service.AuthService
	router  fiber.Router
	cfg     *config.Config
}

func NewAuthHttpHandler(
	service service.AuthService,
	router fiber.Router,
	cfg *config.Config,
) AuthHttpHandler {
	return AuthHttpHandler{service, router, cfg}
}

func (h AuthHttpHandler) RegisterRouter() {
	router := h.router.Group("/auth")

	router.Post("/sign-up", h.SignUp)
	router.Post("/sign-in", h.SignIn)
}

func (h AuthHttpHandler) SignUp(c *fiber.Ctx) error {
	payload := new(models.SignUpRequest)

	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			response.Error(codes.InvalidArgument, err.Error()),
		)
	}

	if errs := validator.ValidateStruct(payload); len(errs) != 0 {
		return c.Status(fiber.StatusBadRequest).JSON(
			response.ValidationFailed(errs),
		)
	}

	res, err := h.service.SignUp(*payload)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			response.Error(err.Code, err.Error()),
		)
	}

	return c.Status(fiber.StatusOK).JSON(response.Success(res))
}

func (h AuthHttpHandler) SignIn(c *fiber.Ctx) error {
	payload := new(models.SignInRequest)

	if err := c.BodyParser(payload); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(
			response.Error(codes.InvalidArgument, err.Error()),
		)
	}

	if errs := validator.ValidateStruct(payload); len(errs) != 0 {
		return c.Status(fiber.StatusBadRequest).JSON(
			response.ValidationFailed(errs),
		)
	}

	res, err := h.service.SignIn(*payload)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(
			response.Error(err.Code, err.Error()),
		)
	}

	return c.Status(fiber.StatusOK).JSON(response.Success(res))
}
