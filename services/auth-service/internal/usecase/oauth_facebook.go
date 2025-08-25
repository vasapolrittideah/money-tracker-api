package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/services/auth-service/internal/domain"
	authtypes "github.com/vasapolrittideah/money-tracker-api/services/auth-service/pkg/types"
)

var (
	ErrInvalidFacebookToken = errors.New("invalid facebook token")
	ErrFacebookTokenExpired = errors.New("facebook token expired")
)

func (u *authUsecase) LoginWithFacebook(
	ctx context.Context,
	params domain.LoginWithFacebookParams,
) (*authtypes.Tokens, error) {
	_, err := u.validateFacebookToken(
		params.AccessToken,
		u.authServiceCfg.Facebook.AppID,
		u.authServiceCfg.Facebook.AppSecret,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to validate facebook token: %v", err)
	}

	userInfo, err := u.getUserInfoFromFacebook(params.AccessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get user info from facebook: %v", err)
	}

	oauthUser := authtypes.OAuthUser{
		Name:  userInfo.Name,
		Email: userInfo.Email,
	}

	return u.linkOAuthAccount(ctx, "FACEBOOK", userInfo.ID, oauthUser)
}

func (u *authUsecase) validateFacebookToken(
	accessToken, appID, appSecret string,
) (*authtypes.FacebookTokenResponse, error) {
	validateURL := fmt.Sprintf(
		"https://graph.facebook.com/debug_token?input_token=%s&access_token=%s|%s",
		accessToken, appID, appSecret,
	)

	resp, err := http.Get(validateURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch facebook token info: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token info response body: %v", err)
	}

	var tokenResp authtypes.FacebookTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to unmarshal token info response body: %v", err)
	}

	if !tokenResp.Data.IsValid {
		return nil, ErrInvalidFacebookToken
	}

	if tokenResp.Data.AppID != appID {
		return nil, ErrInvalidFacebookToken
	}

	if tokenResp.Data.ExpiresAt > 0 && time.Now().Unix() > tokenResp.Data.ExpiresAt {
		return nil, ErrFacebookTokenExpired
	}

	return &tokenResp, nil
}

func (u *authUsecase) getUserInfoFromFacebook(accessToken string) (*authtypes.FacebookUser, error) {
	userURL := fmt.Sprintf(
		"https://graph.facebook.com/me?fields=id,name,email&access_token=%s",
		accessToken,
	)

	userResp, err := http.Get(userURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch facebook user info: %v", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response body: %v", err)
	}

	var user authtypes.FacebookUser
	if err := json.Unmarshal(userBody, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user info response body: %v", err)
	}

	return &user, nil
}
