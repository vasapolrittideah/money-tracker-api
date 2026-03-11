package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery/handler"
)

func RegisterRoutes(
	r chi.Router,
	authHandler *handler.AuthHandler,
	emailVerificationHandler *handler.EmailVerificationHandler,
) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login/email", authHandler.LoginWithEmail)
		r.Post("/register", authHandler.Register)

		r.Route("/email", func(r chi.Router) {
			r.Post("/send-validation", emailVerificationHandler.SendValidationEmail)
			r.Post("/verify", emailVerificationHandler.VerifyEmail)
		})
	})
}
