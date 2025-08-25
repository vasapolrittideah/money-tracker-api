package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"

	"github.com/vasapolrittideah/money-tracker-api/services/auth-service/internal/domain"
	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

var (
	ErrInvalidGoogleAudience = errors.New("invalid google audience")
)

func (u *authUsecase) LoginWithGoogle(
	ctx context.Context,
	params domain.LoginWithGoogleParams,
) (*authtypes.Tokens, error) {
	_, err := u.validateGoogleIDToken(ctx, params.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to validate google id token: %v", err)
	}

	userInfo, err := u.getUserInfoFromGoogle(params.IDToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info from google: %v", err)
	}

	oauthUser := authtypes.OAuthUser{
		Name:  userInfo.Name,
		Email: userInfo.Email,
	}

	return u.linkOAuthAccount(ctx, "GOOGLE", userInfo.Id, oauthUser)
}

func (u *authUsecase) validateGoogleIDToken(ctx context.Context, idToken string) (*oauth2.Tokeninfo, error) {
	oauth2Service, err := oauth2.NewService(ctx, option.WithHTTPClient(&http.Client{}))
	if err != nil {
		return nil, fmt.Errorf("failed to create oauth2 service: %v", err)
	}

	tokenInfoCall := oauth2Service.Tokeninfo()
	tokenInfoCall.IdToken(idToken)
	tokenInfo, err := tokenInfoCall.Do()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google token info: %v", err)
	}

	if tokenInfo.Audience != u.authServiceCfg.Google.ClientID {
		return nil, ErrInvalidGoogleAudience
	}

	return tokenInfo, nil
}

func (u *authUsecase) getUserInfoFromGoogle(idToken string) (*oauth2.Userinfo, error) {
	client := &http.Client{}

	req, err := http.NewRequest(http.MethodGet, "https://www.googleapis.com/oauth2/v1/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create google user info request: %v", err)
	}

	req.Header.Set("Authorization", "Bearer "+idToken)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch google user info: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("status code is not OK")
	}

	var userInfo oauth2.Userinfo
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode user info response body: %v", err)
	}

	return &userInfo, nil
}
