package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// EmailVerification represents a one-time record used to confirm a user's email
// address. Only the SHA-256 hash of the code is stored; once used, the record
// is invalidated and removed automatically by a TTL index when ExpiresAt is reached.
type EmailVerification struct {
	ID         bson.ObjectID `bson:"_id,omitempty"`
	AccountID  string        `bson:"account_id"`
	HashedCode string        `bson:"hashed_code"`
	Used       bool          `bson:"used"`
	ExpiresAt  time.Time     `bson:"expires_at"`
	CreatedAt  time.Time     `bson:"created_at"`
	UpdatedAt  time.Time     `bson:"updated_at"`
}
