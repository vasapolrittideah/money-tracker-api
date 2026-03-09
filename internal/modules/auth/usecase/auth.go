package usecase

import (
	"context"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/database"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/hash"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/token"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

var (
	ErrAccountAlreadyExists = errors.New("account with the given email already exists")
	ErrInvalidCredentials   = errors.New("invalid email or password")
)

type authUseCase struct {
	accountRepo  repository.AccountRepository
	identityRepo repository.IdentityRepository
	sessionRepo  repository.SessionRepository
	transactor   database.Transactor
	jwtMaker     *token.JWTMaker
	bcryptHasher *hash.BcryptHasher
	cryptoHasher *hash.SHA256Hasher
	config       *config.Config
}

// NewAuthUseCase returns a new AuthUseCase with the given dependencies.
func NewAuthUseCase(
	accountRepo repository.AccountRepository,
	identityRepo repository.IdentityRepository,
	sessionRepo repository.SessionRepository,
	transactor database.Transactor,
	jwtMaker *token.JWTMaker,
	bcryptHasher *hash.BcryptHasher,
	cryptoHasher *hash.SHA256Hasher,
	cfg *config.Config,
) usecase.AuthUseCase {
	return &authUseCase{
		accountRepo:  accountRepo,
		identityRepo: identityRepo,
		sessionRepo:  sessionRepo,
		transactor:   transactor,
		jwtMaker:     jwtMaker,
		bcryptHasher: bcryptHasher,
		cryptoHasher: cryptoHasher,
		config:       cfg,
	}
}

// LoginWithEmail implements [usecase.AuthUseCase].
func (u *authUseCase) LoginWithEmail(ctx context.Context, params *usecase.LoginWithEmailParams) (*usecase.AuthResponse, error) {
	account, err := u.accountRepo.GetAccountByEmail(ctx, params.Email)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrInvalidCredentials
		}

		return nil, err
	}

	if ok := u.bcryptHasher.Verify(params.Password, account.HashedPassword); !ok {
		return nil, ErrInvalidCredentials
	}

	if err := u.identityRepo.UpdateLastLogin(ctx, account.ID.Hex()); err != nil {
		return nil, err
	}

	return u.createSession(ctx, account.ID.Hex())
}

// Register implements [usecase.AuthUseCase].
func (u *authUseCase) Register(ctx context.Context, params *usecase.RegisterParams) (*usecase.AuthResponse, error) {
	hashedPassword, err := u.bcryptHasher.Hash(params.Password)
	if err != nil {
		return nil, err
	}

	var accountID string

	if err := u.transactor.WithTransaction(ctx, func(ctx context.Context) error {
		account, err := u.accountRepo.CreateAccount(ctx, &entity.Account{
			Email:          params.Email,
			HashedPassword: hashedPassword,
		})
		if err != nil {
			if mongo.IsDuplicateKeyError(err) {
				return ErrAccountAlreadyExists
			}
			return err
		}

		if _, err := u.identityRepo.CreateIdentity(ctx, &entity.Identity{
			AccountID:  account.ID.Hex(),
			Provider:   "email",
			ProviderID: "",
			Email:      account.Email,
		}); err != nil {
			return err
		}

		accountID = account.ID.Hex()
		return nil
	}); err != nil {
		return nil, err
	}

	return u.createSession(ctx, accountID)
}

// createSession creates a new session for the given account ID and returns
// the generated JWT tokens.
func (u *authUseCase) createSession(ctx context.Context, accountID string) (*usecase.AuthResponse, error) {
	session, err := u.sessionRepo.CreateSession(ctx, &entity.Session{AccountID: accountID})
	if err != nil {
		return nil, err
	}

	accessToken, err := u.generateJWT(
		accountID,
		session.ID.Hex(),
		u.config.JWT.AccessSecretKey,
		u.config.JWT.AccessExpiresIn,
	)
	if err != nil {
		return nil, err
	}

	refreshToken, err := u.generateJWT(
		accountID,
		session.ID.Hex(),
		u.config.JWT.RefreshSecretKey,
		u.config.JWT.RefreshExpiresIn,
	)
	if err != nil {
		return nil, err
	}

	hashedRefreshToken, err := u.cryptoHasher.Hash(refreshToken)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	if _, err := u.sessionRepo.UpdateJWT(ctx, session.ID.Hex(), &repository.UpdateJWTParams{
		AccessToken:        accessToken,
		RefreshToken:       hashedRefreshToken,
		AccessTokenExpiry:  now.Add(u.config.JWT.AccessExpiresIn),
		RefreshTokenExpiry: now.Add(u.config.JWT.RefreshExpiresIn),
	}); err != nil {
		return nil, err
	}

	return &usecase.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
	}, nil
}

// generateJWT creates a JWT token with the given claims and signs it using
// the given secret key.
func (u *authUseCase) generateJWT(accountID, sessionID, secretKey string, expiresIn time.Duration) (string, error) {
	now := time.Now()

	claims := token.JWTClaims{
		AccountID: accountID,
		SessionID: sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(expiresIn)),
			NotBefore: jwt.NewNumericDate(now),
			Issuer:    u.config.JWT.Issuer,
			Audience:  jwt.ClaimStrings{u.config.JWT.Issuer},
		},
	}

	jwt, err := u.jwtMaker.GenerateToken(claims, secretKey)
	if err != nil {
		return "", err
	}

	return jwt, nil
}
