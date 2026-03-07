package database

import (
	"context"
	"time"

	"github.com/vasapolrittideah/money-tracker-api/internal/core/config"
	"github.com/vasapolrittideah/money-tracker-api/internal/core/logger"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// connectionTimeout is the maximum duration allowed for Connect and Disconnect operations.
const connectionTimeout = 20 * time.Second

// MongoDB wraps the official MongoDB client together with its configuration
// and a reference to the target database, providing a convenient lifecycle API.
type MongoDB struct {
	config   *config.DatabaseConfig
	client   *mongo.Client
	database *mongo.Database
}

// NewMongoDB creates a new MongoDB instance with the given configuration.
// Call Connect to establish the actual connection before using the database.
func NewMongoDB(cfg *config.DatabaseConfig) *MongoDB {
	return &MongoDB{config: cfg}
}

// Connect establishes a connection to MongoDB using the configured URI,
// verifies reachability with a ping, and stores the client and database
// references for later use.
func (d *MongoDB) Connect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()

	client, err := mongo.Connect(options.Client().ApplyURI(d.config.Addr))
	if err != nil {
		return err
	}

	d.client = client
	d.database = client.Database(d.config.Name)

	if err := d.client.Ping(ctx, readpref.Primary()); err != nil {
		return err
	}

	logger.Logger.Info().Str("addr", d.config.Addr).Msg("Successfully connected to MongoDB")

	return nil
}

// Disconnect gracefully closes the connection to MongoDB.
// It should be called on application shutdown, typically via defer after Connect.
func (d *MongoDB) Disconnect(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, connectionTimeout)
	defer cancel()

	if err := d.client.Disconnect(ctx); err != nil {
		return err
	}

	logger.Logger.Info().Msg("Successfully disconnected from MongoDB")

	return nil
}

// GetDatabase returns the underlying *mongo.Database for direct collection access.
func (d *MongoDB) GetDatabase() *mongo.Database {
	return d.database
}
