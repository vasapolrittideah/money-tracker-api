package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/contract"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/token"
)

type jwtContextKey string

const claimsContextKey jwtContextKey = "jwt_claims"

// RequireAuth returns a middleware that validates the Bearer JWT in the
// Authorization header and stores the parsed claims in the request context.
// Protected handlers can retrieve the claims with ClaimsFromContext.
func RequireAuth(jwtMaker *token.JWTMaker, accessSecret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				contract.WriteUnauthorizedResponse(w, "missing authorization header")
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") {
				contract.WriteUnauthorizedResponse(w, "authorization header must be Bearer <token>")
				return
			}

			claims := &token.JWTClaims{}
			if _, err := jwtMaker.ValidateTokenWithClaims(parts[1], accessSecret, claims); err != nil {
				fmt.Printf("token validation error: %v\n", err)
				contract.WriteUnauthorizedResponse(w, "invalid or expired token")
				return
			}

			ctx := context.WithValue(r.Context(), claimsContextKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ClaimsFromContext retrieves the JWT claims stored by RequireAuth.
// Returns nil, false if the context does not contain claims.
func ClaimsFromContext(ctx context.Context) (*token.JWTClaims, bool) {
	claims, ok := ctx.Value(claimsContextKey).(*token.JWTClaims)
	return claims, ok
}
