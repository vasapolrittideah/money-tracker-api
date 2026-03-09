package database

import "context"

// Database defines the lifecycle contract for a database connection.
// The type parameter T represents the underlying database client or reference
// returned by GetDatabase (e.g. *mongo.Database).
// Implementations must support establishing and gracefully closing a connection.
type Database[T any] interface {
	// Connect establishes a connection to the database.
	// It should return an error if the connection cannot be established.
	Connect(ctx context.Context) error

	// Disconnect gracefully closes the database connection.
	// It should be called on application shutdown, typically via defer after Connect.
	Disconnect(ctx context.Context) error

	// GetDatabase returns the underlying database client or reference for direct access.
	GetDatabase() T
}

// Transactor defines the contract for running multiple operations atomically.
// Implementations must roll back all changes if fn returns an error, and commit
// them otherwise. The context passed into fn carries the active transaction
// session and must be forwarded to every repository call inside fn.
type Transactor interface {
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
