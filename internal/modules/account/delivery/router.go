package delivery

import (
	"github.com/go-chi/chi/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/delivery/handler"
)

func RegisterRoutes(r chi.Router, accountHandler *handler.AccountHandler) {
	r.Route("/account", func(r chi.Router) {
		r.Get("/me", accountHandler.GetCurrentAccount)
		r.Delete("/delete", accountHandler.DeleteAccount)
	})
}
