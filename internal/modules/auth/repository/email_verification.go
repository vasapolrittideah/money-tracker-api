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

const emailVerificationCollection = "email_verifications"

type emailVerificationRepository struct {
	db *mongo.Database
}

func NewEmailVerificationRepository(ctx context.Context, db *mongo.Database) repository.EmailVerificationRepository {
	collection := db.Collection(emailVerificationCollection)

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "hashed_code", Value: 1}},
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
		logger.Log.Error().Err(err).Msg("failed to create indexes for email_verifications collection")
	}

	return &emailVerificationRepository{db: db}
}

// Create implements [repository.EmailVerificationRepository].
func (e *emailVerificationRepository) Create(ctx context.Context, verification *entity.EmailVerification) (*entity.EmailVerification, error) {
	now := time.Now()
	verification.CreatedAt = now
	verification.UpdatedAt = now
	verification.Used = false

	result, err := e.db.Collection(emailVerificationCollection).InsertOne(ctx, verification)
	if err != nil {
		return nil, err
	}

	if objectID, ok := result.InsertedID.(bson.ObjectID); ok {
		verification.ID = objectID
	}

	return verification, nil
}

// GetByAccountID implements [repository.EmailVerificationRepository].
func (e *emailVerificationRepository) GetByAccountID(ctx context.Context, accountID string) (*entity.EmailVerification, error) {
	filter := bson.M{"account_id": accountID}

	var verification entity.EmailVerification
	err := e.db.Collection(emailVerificationCollection).FindOne(ctx, filter).Decode(&verification)
	if err != nil {
		return nil, err
	}

	return &verification, nil
}

// MarkUsed implements [repository.EmailVerificationRepository].
func (e *emailVerificationRepository) MarkAsUsed(ctx context.Context, id bson.ObjectID) error {
	filter := bson.M{"_id": id}
	update := bson.M{
		"$set": bson.M{
			"used":       true,
			"updated_at": time.Now(),
		},
	}

	_, err := e.db.Collection(emailVerificationCollection).UpdateOne(ctx, filter, update)
	return err
}

// InvalidateAllForAccount implements [repository.EmailVerificationRepository].
func (e *emailVerificationRepository) InvalidateAllForAccount(ctx context.Context, accountID string) error {
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

	_, err = e.db.Collection(emailVerificationCollection).UpdateMany(ctx, filter, update)
	return err
}
