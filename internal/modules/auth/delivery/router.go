package delivery

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery/handler"
)

func RegisterRoutes(
	r chi.Router,
	authHandler *handler.AuthHandler,
	emailVerificationHandler *handler.EmailVerificationHandler,
	authMiddleware func(http.Handler) http.Handler,
) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login/email", authHandler.LoginWithEmail)
		r.Post("/register", authHandler.Register)

		r.Group(func(r chi.Router) {
			r.Use(authMiddleware)
			r.Route("/email", func(r chi.Router) {
				r.Post("/send-verification", emailVerificationHandler.SendVerificationEmail)
				r.Post("/verify", emailVerificationHandler.VerifyEmail)
				r.Post("/change", emailVerificationHandler.ChangeEmail)
			})
		})
	})
}
