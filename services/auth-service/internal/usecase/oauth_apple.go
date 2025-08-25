package usecase

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v2/jwk"

	"github.com/vasapolrittideah/money-tracker-api/services/auth-service/internal/domain"
	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

var (
	AppleIssuer  = "https://appleid.apple.com"
	AppleKeysURL = "https://appleid.apple.com/auth/keys"

	ErrInvalidAppleToken = errors.New("invalid apple token")
	ErrAppleTokenExpired = errors.New("apple token expired")
)

func (u *authUsecase) LoginWithApple(
	ctx context.Context,
	params domain.LoginWithAppleParams,
) (*authtypes.Tokens, error) {
	claims, err := u.verifyAppleIdentityToken(ctx, params.IdentityToken)
	if err != nil {
		return nil, err
	}

	oauthUser := authtypes.OAuthUser{
		Name:  "", // Apple doesn't provide name in the identity token
		Email: claims.Email,
	}

	return u.linkOAuthAccount(ctx, "APPLE", claims.Subject, oauthUser)
}

func (u *authUsecase) verifyAppleIdentityToken(ctx context.Context, idToken string) (*authtypes.AppleClaims, error) {
	keySet, err := jwk.Fetch(ctx, AppleKeysURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch apple public keys: %v", err)
	}

	token, err := jwt.ParseWithClaims(idToken, &authtypes.AppleClaims{}, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		kid, ok := token.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in token header")
		}

		key, found := keySet.LookupKeyID(kid)
		if !found {
			return nil, fmt.Errorf("key not found for kid: %s", kid)
		}

		var publicKey rsa.PublicKey
		if err := key.Raw(&publicKey); err != nil {
			return nil, fmt.Errorf("failed to convert key: %v", err)
		}

		return &publicKey, nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %v", err)
	}

	claims, ok := token.Claims.(*authtypes.AppleClaims)
	if !ok || !token.Valid {
		return nil, ErrInvalidAppleToken
	}

	if claims.Issuer != AppleIssuer {
		return nil, ErrInvalidAppleToken
	}

	if claims.Audience != u.authServiceCfg.Apple.ClientID {
		return nil, ErrInvalidAppleToken
	}

	if claims.ExpirationTime < time.Now().Unix() {
		return nil, ErrAppleTokenExpired
	}

	return claims, nil
}
