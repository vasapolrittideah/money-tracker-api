package database

import "context"

// Database defines the lifecycle contract for a database connection.
// Implementations must support establishing and gracefully closing a connection.
type Database interface {
	// Connect establishes a connection to the database.
	// It should return an error if the connection cannot be established.
	Connect(ctx context.Context) error

	// Disconnect gracefully closes the database connection.
	// It should be called on application shutdown, typically via defer after Connect.
	Disconnect(ctx context.Context) error
}
