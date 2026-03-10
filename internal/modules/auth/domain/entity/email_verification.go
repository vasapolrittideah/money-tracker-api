package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// EmailVerification represents a one-time verification record used to confirm
// a user's email address. A new record is created each time a verification email
// is sent to the user.
//
// The plain-text code is emailed to the user while only its SHA-256 hash is
// stored in the database.
//
// Once the user submits the correct code, Used is set to true and the record
// becomes invalid. Records are automatically removed by a TTL index when
// ExpiresAt is reached.
type EmailVerification struct {
	ID         bson.ObjectID `bson:"_id,omitempty"`
	AccountID  string        `bson:"account_id"`
	HashedCode string        `bson:"hashed_code"`
	Used       bool          `bson:"used"`
	ExpiresAt  time.Time     `bson:"expires_at"`
	CreatedAt  time.Time     `bson:"created_at"`
	UpdatedAt  time.Time     `bson:"updated_at"`
}
