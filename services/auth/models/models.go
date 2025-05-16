package models

import "github.com/vasapolrittideah/money-tracker-api/shared/domain"

type SignUpRequest struct {
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignUpResponse struct {
	domain.User
}

type SignInRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type SignInResponse struct {
	domain.Jwt
}
