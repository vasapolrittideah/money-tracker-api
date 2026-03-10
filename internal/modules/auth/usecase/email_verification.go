package usecase

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/hash"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/mailer"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/usecase"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type emailVerificationUseCase struct {
	accountRepo           repository.AccountRepository
	emailVerificationRepo repository.EmailVerificationRepository
	mailer                *mailer.Mailer
	cryptoHasher          *hash.SHA256Hasher
}

func NewEmailVerificationUseCase(
	accountRepo repository.AccountRepository,
	emailVerificationRepo repository.EmailVerificationRepository,
	mailer *mailer.Mailer,
	cryptoHasher *hash.SHA256Hasher,
) usecase.EmailVerificationUseCase {
	return &emailVerificationUseCase{
		accountRepo:           accountRepo,
		emailVerificationRepo: emailVerificationRepo,
		mailer:                mailer,
		cryptoHasher:          cryptoHasher,
	}
}

// SendValidationEmail implements [usecase.EmailVerificationUseCase].
func (u *emailVerificationUseCase) SendValidationEmail(ctx context.Context, params *usecase.SendValidationEmailParams) error {
	account, err := u.accountRepo.GetAccountByID(ctx, params.AccountID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return auth.ErrAccountNotFound
		}

		return err
	}

	if err := u.emailVerificationRepo.InvalidateAllForAccount(ctx, params.AccountID); err != nil {
		return err
	}

	code, hashedCode, err := u.generateVerificationCode()
	if err != nil {
		return err
	}

	verification := &entity.EmailVerification{
		HashedCode: hashedCode,
		AccountID:  params.AccountID,
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}

	if _, err := u.emailVerificationRepo.Create(ctx, verification); err != nil {
		return err
	}

	htmlBody := fmt.Sprintf(`
	<p>Hi,</p>
	<p>Thank you for registering with Money Tracker!</p>
	<p>Please use the verification code below to verify your email address:</p>

	<h2 style="letter-spacing: 8px; font-size: 32px; text-align: center; color: #4F46E5;">%s</h2>

	<p>This code will expire in <strong>%s</strong>.</p>
	<p>If you did not create an account, you can safely ignore this email.</p>

	<p>Thank you,</p>
	<p>Money Tracker Team</p>
	`, code, time.Until(verification.ExpiresAt).Round(time.Minute).String())

	if err := u.mailer.SendHTML([]string{account.Email}, "Verify your email", htmlBody); err != nil {
		return err
	}

	return nil
}

// VerifyEmail implements [usecase.EmailVerificationUseCase].
func (u *emailVerificationUseCase) VerifyEmail(ctx context.Context, params *usecase.VerifyEmailParams) error {
	verification, err := u.emailVerificationRepo.GetByAccountID(ctx, params.AccountID)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return auth.ErrEmailVerificationNotFound
		}

		return err
	}

	if verification.Used {
		return auth.ErrEmailVerificationUsed
	}

	if time.Now().After(verification.ExpiresAt) {
		return auth.ErrEmailVerificationExpired
	}

	if ok := u.cryptoHasher.Verify(params.Code, verification.HashedCode); !ok {
		return auth.ErrEmailVerificationInvalid
	}

	if err := u.emailVerificationRepo.MarkAsUsed(ctx, verification.ID); err != nil {
		return err
	}

	return nil
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
