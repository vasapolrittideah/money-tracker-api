package repository

import (
	"context"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const passwordResetCollection = "password_resets"

type passwordResetRepository struct {
	db *mongo.Database
}

func NewPasswordResetRepository(ctx context.Context, db *mongo.Database) repository.PasswordResetRepository {
	collection := db.Collection(passwordResetCollection)

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "jti", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
		{
			Keys:    bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().SetExpireAfterSeconds(0),
		},
		{
			Keys: bson.D{{Key: "account_id", Value: 1}},
		},
	}

	if _, err := collection.Indexes().CreateMany(ctx, indexes); err != nil {
		logger.Log.Error().Err(err).Msg("failed to create indexes for password_resets collection")
	}

	return &passwordResetRepository{db: db}
}

// Create implements [repository.PasswordResetRepository].
func (r *passwordResetRepository) Create(ctx context.Context, passwordReset *entity.PasswordReset) (*entity.PasswordReset, error) {
	now := time.Now()
	passwordReset.CreatedAt = now
	passwordReset.UpdatedAt = now
	passwordReset.Used = false

	result, err := r.db.Collection(passwordResetCollection).InsertOne(ctx, passwordReset)
	if err != nil {
		return nil, err
	}

	if objectID, ok := result.InsertedID.(bson.ObjectID); ok {
		passwordReset.ID = objectID
	}

	return passwordReset, nil
}

// GetByJTI implements [repository.PasswordResetRepository].
func (r *passwordResetRepository) GetByJTI(ctx context.Context, jti string) (*entity.PasswordReset, error) {
	filter := bson.M{"jti": jti}

	var passwordReset entity.PasswordReset
	err := r.db.Collection(passwordResetCollection).FindOne(ctx, filter).Decode(&passwordReset)
	if err != nil {
		return nil, err
	}

	return &passwordReset, nil
}

// InvalidateAllForAccount implements [repository.PasswordResetRepository].
func (r *passwordResetRepository) InvalidateAllForAccount(ctx context.Context, accountID string) error {
	objectID, err := bson.ObjectIDFromHex(accountID)
	if err != nil {
		return err
	}

	filter := bson.M{
		"account_id": objectID,
		"used":       false,
	}
	update := bson.M{
		"$set": bson.M{
			"used":       true,
			"updated_at": time.Now(),
		},
	}

	_, err = r.db.Collection(passwordResetCollection).UpdateMany(ctx, filter, update)
	return err
}

// MarkAsUsed implements [repository.PasswordResetRepository].
func (r *passwordResetRepository) MarkAsUsed(ctx context.Context, jti string) error {
	filter := bson.M{"jti": jti}
	update := bson.M{
		"$set": bson.M{
			"used":       true,
			"updated_at": time.Now(),
		},
	}

	_, err := r.db.Collection(passwordResetCollection).UpdateOne(ctx, filter, update)
	return err
}
