package usecase

import (
	"context"
	"errors"
	"fmt"

	userpbv1 "github.com/vasapolrittideah/money-tracker-api/protogen/user/v1"
	"github.com/vasapolrittideah/money-tracker-api/shared/config"
	"github.com/vasapolrittideah/money-tracker-api/shared/domain"
	"github.com/vasapolrittideah/money-tracker-api/shared/errors/apperror"
	"github.com/vasapolrittideah/money-tracker-api/shared/errors/grpcerror"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	googleOAuth "google.golang.org/api/oauth2/v2"
	"google.golang.org/api/option"
	"gorm.io/gorm"
)

type oauthGoogleUsecase struct {
	userClient        userpbv1.UserServiceClient
	authUsecase       domain.AuthUsecase
	authRepo          domain.AuthRepository
	oauthGoogleConfig *oauth2.Config
	config            *config.Config
}

func NewOAuthGoogleUsecase(
	userClient userpbv1.UserServiceClient,
	authUsecase domain.AuthUsecase,
	authRepo domain.AuthRepository,
	config *config.Config,
) domain.OAuthGoogleUsecase {
	oauthGoogleConfig := &oauth2.Config{
		ClientID:     config.OAuthGoogle.ClientID,
		ClientSecret: config.OAuthGoogle.ClientSecret,
		RedirectURL:  config.OAuthGoogle.RedirectURL,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
		Endpoint: google.Endpoint,
	}

	return &oauthGoogleUsecase{
		userClient:        userClient,
		authUsecase:       authUsecase,
		authRepo:          authRepo,
		oauthGoogleConfig: oauthGoogleConfig,
		config:            config,
	}
}

func (u *oauthGoogleUsecase) GetSignInWithGoogleURL(state string) string {
	return u.oauthGoogleConfig.AuthCodeURL(state, oauth2.AccessTypeOffline)
}

func (u *oauthGoogleUsecase) HandleGoogleCallback(ctx context.Context, code string) (*domain.Token, error) {
	userInfo, err := getGoogleUserInfo(code, u.oauthGoogleConfig)
	if err != nil {
		return nil, apperror.NewError(apperror.ErrInternal, err.Error())
	}

	// Check if Google account already linked
	externalAuth, err := u.authRepo.GetExternalAuthByProviderID(ctx, userInfo.Id)
	if err == nil {
		// Google account already linked, generate tokens
		token, err := generateTokens(externalAuth.UserID, &u.config.JWT)
		if err != nil {
			return nil, apperror.NewError(apperror.ErrInternal, err.Error())
		}

		return token, nil
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, apperror.NewError(apperror.ErrInternal, err.Error())
	}

	// Try to find local user by Google email
	res, err := u.userClient.GetUserByEmail(ctx, &userpbv1.GetUserByEmailRequest{
		Email: userInfo.Email,
	})

	var userID uint64

	if err != nil {
		appErr := grpcerror.ToAppError(err).(*apperror.AppError)
		if appErr.Code != apperror.ErrNotFound {
			return nil, appErr
		}

		// User not found, create new local user
		created, err := u.userClient.CreateUser(ctx, &userpbv1.CreateUserRequest{
			FullName: userInfo.Name,
			Email:    userInfo.Email,
			Password: "",
		})
		if err != nil {
			return nil, grpcerror.ToAppError(err)
		}

		userID = created.User.Id
	} else {
		userID = res.User.Id
	}

	// Link Google account to local user
	_, err = u.authRepo.CreateExternalAuth(ctx, &domain.ExternalAuth{
		ProviderID: userInfo.Id,
		Provider:   "GOOGLE",
		UserID:     userID,
	})
	if err != nil {
		return nil, err
	}

	// Generate token for newly created and linked user
	token, err := generateTokens(userID, &u.config.JWT)
	if err != nil {
		return nil, apperror.NewError(apperror.ErrInternal, err.Error())
	}

	return token, nil
}

func getGoogleUserInfo(code string, config *oauth2.Config) (*googleOAuth.Userinfo, error) {
	token, err := config.Exchange(context.Background(), code)
	if err != nil {
		return nil, fmt.Errorf("failed to exchange token: %v", err)
	}

	client := config.Client(context.Background(), token)
	svc, err := googleOAuth.NewService(context.Background(), option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to create service: %v", err)
	}

	userInfo, err := svc.Userinfo.Get().Do()
	if err != nil {
		return nil, fmt.Errorf("failed to get user info from Google: %v", err)
	}

	return userInfo, nil
}
