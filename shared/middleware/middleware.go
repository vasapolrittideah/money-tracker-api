package middleware

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/response"
	"github.com/vasapolrittideah/money-tracker-api/shared/utils/jwt_util"
	"google.golang.org/grpc/codes"
)

type CoreMiddleware interface {
	Authenticate(tokenType TokenType) fiber.Handler
}

type coreMiddleware struct {
	cfg *config.Config
}

func NewCoreMiddleware(cfg *config.Config) CoreMiddleware {
	return &coreMiddleware{cfg}
}

type TokenType int

const (
	AccessToken TokenType = iota
	RefreshToken
)

func (m coreMiddleware) Authenticate(tokenType TokenType) fiber.Handler {
	return func(c *fiber.Ctx) error {
		const bearer = "Bearer"
		token := c.Get("Authorization")
		if token == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error(codes.Unauthenticated, "No Authorization header found"),
			)
		}

		headerParts := strings.Split(token, " ")
		if len(headerParts) != 2 || headerParts[0] != bearer {
			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error(codes.Unauthenticated, "Malformed Authorization header"),
			)
		}

		var publicKey string
		switch tokenType {
		case AccessToken:
			publicKey = m.cfg.Security.AccessTokenPublicKey
		case RefreshToken:
			publicKey = m.cfg.Security.RefreshTokenPublicKey
		}

		claims, err := jwt_util.ParseToken(headerParts[1], publicKey)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(
				response.Error(codes.Unauthenticated, err.Error()),
			)
		}

		c.Locals("token", headerParts[1])
		c.Locals("sub", (*claims)["sub"])

		return c.Next()
	}
}
