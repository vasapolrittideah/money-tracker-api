package repository

import (
	"context"
	"errors"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/entity"
	"github.com/vasapolrittideah/money-tracker-api/internal/modules/account/domain/repository"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const accountCollection = "accounts"

type accountRepository struct {
	db *mongo.Database
}

func NewAccountRepository(ctx context.Context, db *mongo.Database) repository.AccountRepository {
	collection := db.Collection(accountCollection)

	indexes := []mongo.IndexModel{
		{
			Keys:    bson.D{{Key: "email", Value: 1}},
			Options: options.Index().SetUnique(true),
		},
	}

	if _, err := collection.Indexes().CreateMany(ctx, indexes); err != nil {
		logger.Log.Error().Err(err).Msg("failed to create indexes for accounts collection")
	}

	return &accountRepository{db: db}
}

// CreateAccount implements [repository.AccountRepository].
func (r *accountRepository) CreateAccount(ctx context.Context, account *entity.Account) (*entity.Account, error) {
	now := time.Now()
	account.CreatedAt = now
	account.UpdatedAt = now

	result, err := r.db.Collection(accountCollection).InsertOne(ctx, account)
	if err != nil {
		return nil, err
	}

	if objectID, ok := result.InsertedID.(bson.ObjectID); ok {
		account.ID = objectID
	} else {
		return nil, errors.New("failed to convert insertedID to ObjectID")
	}

	return account, nil
}

// ListAccounts implements [repository.AccountRepository].
func (r *accountRepository) ListAccounts(ctx context.Context, params *repository.FilterAccountsParams) ([]*entity.Account, error) {
	findOptions := options.Find()

	limit := params.Limit
	if limit == 0 {
		limit = 20 // Default limit to prevent unbounded queries
	}
	findOptions.SetLimit(int64(limit))

	if params.Offset > 0 {
		findOptions.SetSkip(int64(params.Offset))
	}

	sortBy := "created_at"
	if params.SortBy != nil {
		sortBy = *params.SortBy
	}

	sortOrder := -1
	if !params.SortDesc {
		sortOrder = 1
	}
	findOptions.SetSort(bson.D{{Key: sortBy, Value: sortOrder}})

	filter := bson.M{}
	if params.Email != nil {
		filter["email"] = *params.Email
	}
	if params.Verified != nil {
		filter["verified"] = *params.Verified
	}

	cursor, err := r.db.Collection(accountCollection).Find(ctx, filter, findOptions)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var accounts []*entity.Account
	for cursor.Next(ctx) {
		var account entity.Account
		if err := cursor.Decode(&account); err != nil {
			return nil, err
		}
		accounts = append(accounts, &account)
	}

	if err := cursor.Err(); err != nil {
		return nil, err
	}

	return accounts, nil
}

// GetAccountByID implements [repository.AccountRepository].
func (r *accountRepository) GetAccountByID(ctx context.Context, id string) (*entity.Account, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	result := r.db.Collection(accountCollection).FindOne(ctx, bson.M{"_id": objectID})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var account entity.Account
	if err := result.Decode(&account); err != nil {
		return nil, err
	}

	return &account, nil
}

// GetAccountByEmail implements [repository.AccountRepository].
func (r *accountRepository) GetAccountByEmail(ctx context.Context, email string) (*entity.Account, error) {
	result := r.db.Collection(accountCollection).FindOne(ctx, bson.M{"email": email})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var account entity.Account
	if err := result.Decode(&account); err != nil {
		return nil, err
	}

	return &account, nil
}

// UpdateAccount implements [repository.AccountRepository].
func (r *accountRepository) UpdateAccount(ctx context.Context, id string, params *repository.UpdateAccountParams) (*entity.Account, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	update := bson.M{}
	if params.Email != nil {
		update["email"] = *params.Email
	}
	if params.HashedPassword != nil {
		update["hashed_password"] = *params.HashedPassword
	}

	if len(update) == 0 {
		return nil, errors.New("no fields to update")
	}

	update["updated_at"] = time.Now()

	result := r.db.Collection(accountCollection).FindOneAndUpdate(
		ctx,
		bson.M{"_id": objectID},
		bson.M{"$set": update},
		options.FindOneAndUpdate().SetReturnDocument(options.After),
	)
	if result.Err() != nil {
		return nil, result.Err()
	}

	var updatedAccount entity.Account
	if err := result.Decode(&updatedAccount); err != nil {
		return nil, err
	}

	return &updatedAccount, nil
}

// DeleteAccount implements [repository.AccountRepository].
func (r *accountRepository) DeleteAccount(ctx context.Context, id string) (*entity.Account, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	result := r.db.Collection(accountCollection).FindOneAndDelete(ctx, bson.M{"_id": objectID})
	if result.Err() != nil {
		return nil, result.Err()
	}

	var deletedAccount entity.Account
	if err := result.Decode(&deletedAccount); err != nil {
		return nil, err
	}

	return &deletedAccount, nil
}
