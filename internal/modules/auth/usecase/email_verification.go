package usecase

import (
	"bytes"
	"context"
	"crypto/rand"
	_ "embed"
	"errors"
	"fmt"
	"html/template"
	"math/big"
	"time"

	"github.com/aws/smithy-go/ptr"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/database"
	apperr "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	core_errors "github.com/vasapolrittideah/money-tracker-api/internal/core/errors"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/hash"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/mailer"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/middleware"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/utils"
	account_repo "github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

//go:embed templates/email_verification.html
var emailVerificationTemplate string

type emailVerificationUseCase struct {
	accountRepo           account_repo.AccountRepository
	emailVerificationRepo repository.EmailVerificationRepository
	transactor            database.Transactor
	mailer                *mailer.Mailer
	cryptoHasher          *hash.SHA256Hasher
}

func NewEmailVerificationUseCase(
	accountRepo account_repo.AccountRepository,
	emailVerificationRepo repository.EmailVerificationRepository,
	transactor database.Transactor,
	cryptoHasher *hash.SHA256Hasher,
	m *mailer.Mailer,
) usecase.EmailVerificationUseCase {
	return &emailVerificationUseCase{
		accountRepo:           accountRepo,
		emailVerificationRepo: emailVerificationRepo,
		transactor:            transactor,
		cryptoHasher:          cryptoHasher,
		mailer:                m,
	}
}

// SendVerificationEmail implements [usecase.EmailVerificationUseCase].
func (u *emailVerificationUseCase) SendVerificationEmail(ctx context.Context) error {
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

	code, hashedCode, err := u.generateVerificationCode()
	if err != nil {
		return err
	}

	verification := &entity.EmailVerification{
		HashedCode: hashedCode,
		AccountID:  claims.AccountID,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	if err := u.transactor.WithTransaction(ctx, func(ctx context.Context) error {
		if err := u.emailVerificationRepo.InvalidateAllForAccount(ctx, claims.AccountID); err != nil {
			return err
		}

		if _, err := u.emailVerificationRepo.Create(ctx, verification); err != nil {
			return err
		}

		return nil
	}); err != nil {
		return err
	}

	tmpl, err := template.New("email_verification").Parse(emailVerificationTemplate)
	if err != nil {
		return err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, map[string]string{
		"Code":      code,
		"ExpiresIn": utils.FormatDuration(time.Until(verification.ExpiresAt)),
	}); err != nil {
		return err
	}
	htmlBody := buf.String()

	if err := u.mailer.SendHTML([]string{account.Email}, "Verify your email", htmlBody); err != nil {
		return err
	}

	return nil
}

// VerifyEmail implements [usecase.EmailVerificationUseCase].
func (u *emailVerificationUseCase) VerifyEmail(ctx context.Context, params *usecase.VerifyEmailParams) error {
	claims, ok := middleware.ClaimsFromContext(ctx)
	if !ok {
		return core_errors.ErrUnauthenticated
	}

	verification, err := u.emailVerificationRepo.GetByAccountID(ctx, claims.AccountID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return apperr.ErrEmailVerificationNotFound
		}
		return err
	}

	if verification.Used {
		return apperr.ErrEmailVerificationCodeUsed
	}

	if time.Now().After(verification.ExpiresAt) {
		return apperr.ErrEmailVerificationCodeExpired
	}

	if ok := u.cryptoHasher.Verify(params.Code, verification.HashedCode); !ok {
		return apperr.ErrEmailVerificationCodeInvalid
	}

	return u.transactor.WithTransaction(ctx, func(ctx context.Context) error {
		if err := u.emailVerificationRepo.MarkAsUsed(ctx, verification.ID); err != nil {
			return err
		}

		if _, err := u.accountRepo.UpdateAccount(ctx, claims.AccountID, &account_repo.UpdateAccountParams{
			Verified: ptr.Bool(true),
		}); err != nil {
			return err
		}

		return nil
	})
}

// ChangeEmail implements [usecase.EmailVerificationUseCase].
func (u *emailVerificationUseCase) ChangeEmail(ctx context.Context, params *usecase.ChangeEmailParams) error {
	if params.OldEmail == params.NewEmail {
		return apperr.ErrEmailUnchanged
	}

	account, err := u.accountRepo.GetAccountByEmail(ctx, params.OldEmail)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return apperr.ErrAccountNotFound
		}
		return err
	}

	account.Email = params.NewEmail

	update := &account_repo.UpdateAccountParams{
		Email: &account.Email,
	}
	if _, err := u.accountRepo.UpdateAccount(ctx, account.ID.Hex(), update); err != nil {
		return err
	}

	return u.SendVerificationEmail(ctx)
}

func (u *emailVerificationUseCase) generateVerificationCode() (string, string, error) {
	n, _ := rand.Int(rand.Reader, big.NewInt(900000))
	code := fmt.Sprintf("%06d", n.Int64()+100000)
	hashedCode, err := u.cryptoHasher.Hash(code)
	if err != nil {
		return "", "", err
	}
	return code, hashedCode, nil
}
