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

const sessionCollection = "sessions"

type sessionRepository struct {
	db *mongo.Database
}

func NewSessionRepository(db *mongo.Database) repository.SessionRepository {
	return &sessionRepository{db: db}
}

// CreateSession implements [repository.SessionRepository].
func (r *sessionRepository) CreateSession(ctx context.Context, session *entity.Session) (*entity.Session, error) {
	now := time.Now()
	session.CreatedAt = now
	session.UpdatedAt = now

	result, err := r.db.Collection(sessionCollection).InsertOne(ctx, session)
	if err != nil {
		return nil, err
	}

	if objectID, ok := result.InsertedID.(bson.ObjectID); ok {
		session.ID = objectID
	} else {
		return nil, errors.New("failed to convert insertedID to ObjectID")
	}

	return session, nil
}

// GetSessionByAccountID implements [repository.SessionRepository].
func (r *sessionRepository) GetSessionByAccountID(ctx context.Context, accountID string) (*entity.Session, error) {
	result := r.db.Collection(sessionCollection).FindOne(ctx, bson.M{"account_id": accountID})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var session entity.Session
	if err := result.Decode(&session); err != nil {
		return nil, err
	}

	return &session, nil
}

// UpdateJWT implements [repository.SessionRepository].
func (r *sessionRepository) UpdateJWT(ctx context.Context, id string, params *repository.UpdateJWTParams) (*entity.Session, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	update := bson.M{
		"access_token":         params.AccessToken,
		"refresh_token":        params.RefreshToken,
		"access_token_expiry":  params.AccessTokenExpiry,
		"refresh_token_expiry": params.RefreshTokenExpiry,
		"updated_at":           time.Now(),
	}

	result := r.db.Collection(sessionCollection).FindOneAndUpdate(
		ctx,
		bson.M{"_id": objectID},
		bson.M{"$set": update},
	)

	if result.Err() != nil {
		return nil, result.Err()
	}

	var updatedSession entity.Session
	if err := result.Decode(&updatedSession); err != nil {
		return nil, err
	}

	return &updatedSession, nil
}

// DeleteSession implements [repository.SessionRepository].
func (r *sessionRepository) DeleteSession(ctx context.Context, id string) (*entity.Session, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	result := r.db.Collection(sessionCollection).FindOneAndDelete(ctx, bson.M{"_id": objectID})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var deletedSession entity.Session
	if err := result.Decode(&deletedSession); err != nil {
		return nil, err
	}

	return &deletedSession, nil
}
