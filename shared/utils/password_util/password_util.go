package password_util

import (
	"fmt"

	"github.com/matthewhartstonge/argon2"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"google.golang.org/grpc/codes"
)

func HashPassword(password string) (string, *app_error.Error) {
	argon := argon2.DefaultConfig()
	encoded, err := argon.HashEncoded([]byte(password))
	if err != nil {
		return "", app_error.New(codes.Internal, fmt.Errorf("unable to hash password: %v", err.Error()))
	}

	return string(encoded), nil
}

func VerifyPassword(encoded string, password string) (bool, error) {
	return argon2.VerifyEncoded([]byte(encoded), []byte(password))
}
