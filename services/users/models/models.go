package models

import "github.com/google/uuid"

type GetOrderByIDRequest struct {
	ID uuid.UUID `json:"id"`
}

type GetOrderByEmailRequest struct {
	Email string `json:"email"`
}
