package jwt_util

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	"github.com/matthewhartstonge/argon2"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain/app_error"
	"google.golang.org/grpc/codes"
)

func GenerateJwt(ttl time.Duration, privateKey string, userId uuid.UUID) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil {
		return "", app_error.New(codes.Internal, fmt.Errorf("unable to decode private key: %v", err.Error()))
	}

	key, err := jwt.ParseRSAPrivateKeyFromPEM(decoded)
	if err != nil {
		return "", app_error.New(codes.Internal, fmt.Errorf("unable to parse private key: %v", err.Error()))
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"sub": userId.String(),
		"exp": now.Add(ttl).Unix(),
		"iat": now.Unix(),
	}

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", app_error.New(codes.Internal, fmt.Errorf("unable to sign token: %v", err.Error()))
	}

	return token, nil
}

func ValidateJwt(token string, publicKey string) (*jwt.Token, error) {
	decodedPublicKey, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("unable to decode public key: %v", err.Error()))
	}

	key, err := jwt.ParseECPublicKeyFromPEM(decodedPublicKey)
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("unable to parse public key: %v", err.Error()))
	}

	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, app_error.New(
				codes.Internal,
				fmt.Errorf("unexpected signing method: %v", t.Header["alg"].(string)),
			)
		}

		return key, nil
	})
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("unable to parse token: %v", err.Error()))
	}

	return parsed, nil
}

func ParseToken(tokenString, tokenPublicKey string) (*jwt.MapClaims, error) {
	token, err := ValidateJwt(tokenString, tokenPublicKey)
	if err != nil {
		return nil, app_error.New(codes.Internal, fmt.Errorf("token is invalid or has been expired"))
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, app_error.New(codes.Unauthenticated, fmt.Errorf("token is invalid"))
	}

	return &claims, nil
}

func HashRefreshToken(refreshToken string) (string, error) {
	argon := argon2.DefaultConfig()

	encoded, err := argon.HashEncoded([]byte(refreshToken))
	if err != nil {
		return "", app_error.New(codes.Internal, fmt.Errorf("unable to hash refresh token: %v", err.Error()))
	}

	return string(encoded), nil
}

func VerifyRefreshToken(encoded string, refreshToken string) (bool, error) {
	return argon2.VerifyEncoded([]byte(refreshToken), []byte(encoded))
}
