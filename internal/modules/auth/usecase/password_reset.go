package usecase

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/database"
	apperr "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/hash"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/mailer"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/middleware"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/token"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
	account_repo "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

//go:embed templates
var passwordResetTemplateFS embed.FS

type passwordResetUseCase struct {
	accountRepo       account_repo.AccountRepository
	passwordResetRepo repository.PasswordResetRepository
	transactor        database.Transactor
	mailer            *mailer.Mailer
	jwtMaker          *token.JWTMaker
	bcryptHasher      *hash.BcryptHasher
	config            *config.Config
}

func NewPasswordResetUseCase(
	accountRepo account_repo.AccountRepository,
	passwordResetRepo repository.PasswordResetRepository,
	transactor database.Transactor,
	m *mailer.Mailer,
	jwtMaker *token.JWTMaker,
	bcryptHasher *hash.BcryptHasher,
	config *config.Config,
) usecase.PasswordResetUseCase {
	return &passwordResetUseCase{
		accountRepo:       accountRepo,
		passwordResetRepo: passwordResetRepo,
		transactor:        transactor,
		mailer:            m,
		jwtMaker:          jwtMaker,
		bcryptHasher:      bcryptHasher,
		config:            config,
	}
}

// SendPasswordResetEmail implements [usecase.PasswordResetUseCase].
func (u *passwordResetUseCase) SendPasswordResetEmail(ctx context.Context) error {
	claims, ok := middleware.ClaimsFromContext(ctx)
	if !ok {
		return apperr.ErrUnauthenticated
	}

	account, err := u.accountRepo.GetAccountByID(ctx, claims.AccountID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return apperr.ErrAccountNotFound
		}
		return err
	}

	tokenStr, jti, err := u.generateResetToken(account.ID.Hex())
	if err != nil {
		return err
	}

	resetToken := &entity.PasswordReset{
		JTI:       jti,
		AccountID: account.ID.Hex(),
		Used:      false,
		ExpiresAt: time.Now().Add(u.config.JWT.PasswordResetExpiresIn),
	}

	if err := u.transactor.WithTransaction(ctx, func(ctx context.Context) error {
		if err := u.passwordResetRepo.InvalidateAllForAccount(ctx, claims.AccountID); err != nil {
			return err
		}

		if _, err := u.passwordResetRepo.Create(ctx, resetToken); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	locale := "en"
	if strings.HasPrefix(strings.ToLower(middleware.LanguageFromContext(ctx)), "th") {
		locale = "th"
	}

	tmplFile := fmt.Sprintf("templates/password_reset.%s.html", locale)
	tmplContent, err := passwordResetTemplateFS.ReadFile(tmplFile)
	if err != nil {
		return err
	}

	tmpl, err := template.New("password_reset").Parse(string(tmplContent))
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{
		"ResetLink": fmt.Sprintf("%sreset-password?token=%s", u.config.App.ClientURL, tokenStr),
		"ExpiresIn": utils.FormatDuration(time.Until(resetToken.ExpiresAt)),
	}); err != nil {
		return err
	}

	subject := map[string]string{
		"en": "Reset your password",
		"th": "รีเซ็ตรหัสผ่านของคุณ",
	}[locale]

	if err := u.mailer.SendHTML([]string{account.Email}, subject, buf.String()); err != nil {
		return err
	}

	return nil
}

// ResetPassword implements [usecase.PasswordResetUseCase].
func (u *passwordResetUseCase) ResetPassword(ctx context.Context, params *usecase.ResetPasswordParams) error {
	claims, ok := middleware.ClaimsFromContext(ctx)
	if !ok {
		return apperr.ErrUnauthenticated
	}

	resetToken, err := u.passwordResetRepo.GetByJTI(ctx, params.JTI)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return apperr.ErrPasswordResetTokenNotFound
		}
		return err
	}

	if resetToken.Used {
		return apperr.ErrPasswordResetTokenUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return apperr.ErrPasswordResetTokenExpired
	}

	HashedPassword, err := u.bcryptHasher.Hash(params.NewPassword)
	if err != nil {
		return err
	}

	if _, err := u.accountRepo.UpdateAccount(ctx, claims.AccountID, &account_repo.UpdateAccountParams{
		HashedPassword: &HashedPassword,
	}); err != nil {
		return err
	}

	if err := u.passwordResetRepo.MarkAsUsed(ctx, params.JTI); err != nil {
		return err
	}

	return nil
}

// ValidateResetToken implements [usecase.PasswordResetUseCase].
func (u *passwordResetUseCase) ValidateResetToken(ctx context.Context, params *usecase.ValidateResetTokenParams) error {
	resetToken, err := u.passwordResetRepo.GetByJTI(ctx, params.JTI)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return apperr.ErrPasswordResetTokenNotFound
		}
		return err
	}

	if resetToken.Used {
		return apperr.ErrPasswordResetTokenUsed
	}

	if time.Now().After(resetToken.ExpiresAt) {
		return apperr.ErrPasswordResetTokenExpired
	}

	return nil
}

func (u *passwordResetUseCase) generateResetToken(accountID string) (string, string, error) {
	jti, err := generateJTI(32)
	if err != nil {
		return "", "", err
	}

	now := time.Now()
	claims := token.JTIClaims{
		AccountID: accountID,
		JTI:       jti,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    u.config.JWT.Issuer,
			Audience:  jwt.ClaimStrings{u.config.JWT.Issuer},
			Subject:   accountID,
			ExpiresAt: jwt.NewNumericDate(now.Add(u.config.JWT.PasswordResetExpiresIn)),
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
		},
	}

	tokenStr, err := u.jwtMaker.GenerateToken(claims, u.config.JWT.PasswordResetSecretKey)
	if err != nil {
		return "", "", err
	}

	return tokenStr, jti, nil
}

func generateJTI(size int) (string, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
