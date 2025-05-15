package models

import "github.com/google/uuid"

type GetOrderByIdRequest struct {
	Id uuid.UUID `json:"id"`
}

type GetOrderByEmailRequest struct {
	Email string `json:"email"`
}
