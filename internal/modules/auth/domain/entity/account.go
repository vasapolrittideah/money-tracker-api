package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Account represents a user's authentication record stored in the database.
// It holds the credentials and email-verification state for a registered user.
type Account struct {
	ID             bson.ObjectID `bson:"_id,omitempty"`
	Email          string        `bson:"email"`
	HashedPassword string        `bson:"hashed_password"`
	Verified       bool          `bson:"verified"`
	CreatedAt      time.Time     `bson:"created_at"`
	UpdatedAt      time.Time     `bson:"updated_at"`
}
