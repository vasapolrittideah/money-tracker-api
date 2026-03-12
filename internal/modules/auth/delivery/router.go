package delivery

import (
	"github.com/go-chi/chi/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery/handler"
)

func RegisterRoutes(
	r chi.Router,
	authHandler *handler.AuthHandler,
) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login/email", authHandler.LoginWithEmail)
		r.Post("/register", authHandler.Register)
	})
}

func RegisterProtectedRoutes(
	r chi.Router,
	emailVerificationHandler *handler.EmailVerificationHandler,
) {
	r.Route("/auth", func(r chi.Router) {
		r.Route("/email", func(r chi.Router) {
			r.Post("/send-verification", emailVerificationHandler.SendVerificationEmail)
			r.Post("/verify", emailVerificationHandler.VerifyEmail)
			r.Post("/change", emailVerificationHandler.ChangeEmail)
		})
	})
}
