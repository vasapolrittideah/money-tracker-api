package repository

import (
	"context"
	"errors"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/auth/domain/repository"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const identityCollection = "identities"

type identityRepository struct {
	db *mongo.Database
}

func NewIdentityRepository(db *mongo.Database) repository.IdentityRepository {
	return &identityRepository{db: db}
}

// CreateIdentity implements [repository.IdentityRepository].
func (r *identityRepository) CreateIdentity(ctx context.Context, identity *entity.Identity) (*entity.Identity, error) {
	now := time.Now()
	identity.CreatedAt = now
	identity.UpdatedAt = now

	result, err := r.db.Collection(identityCollection).InsertOne(ctx, identity)
	if err != nil {
		return nil, err
	}

	if objectID, ok := result.InsertedID.(bson.ObjectID); ok {
		identity.ID = objectID
	} else {
		return nil, errors.New("failed to convert insertedID to ObjectID")
	}

	return identity, nil
}

// ListIdentitiesByAccountID implements [repository.IdentityRepository].
func (r *identityRepository) ListIdentitiesByAccountID(ctx context.Context, accountID string) ([]*entity.Identity, error) {
	cursor, err := r.db.Collection(identityCollection).Find(ctx, bson.M{"account_id": accountID})
	if err != nil {
		return nil, err
	}

	var identities []*entity.Identity
	if err := cursor.All(ctx, &identities); err != nil {
		return nil, err
	}

	return identities, nil
}

// GetIdentityByProvider implements [repository.IdentityRepository].
func (r *identityRepository) GetIdentityByProvider(ctx context.Context, provider string, providerID string) (*entity.Identity, error) {
	result := r.db.Collection(identityCollection).FindOne(ctx, bson.M{
		"provider_id": providerID,
		"provider":    provider,
	})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var identity entity.Identity
	if err := result.Decode(&identity); err != nil {
		return nil, err
	}

	return &identity, nil
}

// UpdateLastLogin implements [repository.IdentityRepository].
func (r *identityRepository) UpdateLastLogin(ctx context.Context, accountID string) error {
	_, err := r.db.Collection(identityCollection).UpdateOne(
		ctx,
		bson.M{"account_id": accountID},
		bson.M{"$set": bson.M{"last_login_at": time.Now()}},
	)

	return err
}
