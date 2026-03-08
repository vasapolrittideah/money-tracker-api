package router

import (
	"github.com/go-chi/chi/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/delivery/handler"
)

func RegisterRoutes(r chi.Router, h *handler.AuthHandler) {
	r.Route("/auth", func(r chi.Router) {
		r.Post("/login/email", h.LoginWithEmail)
		r.Post("/register", h.Register)
	})
}
