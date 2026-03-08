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
	CreatedAt      time.Time     `bson:"created_at"`
	UpdatedAt      time.Time     `bson:"updated_at"`

	// Verified indicates whether the user has confirmed their email address.
	Verified bool `bson:"verified"`

	// EmailVerificationToken is the one-time token sent to the user's inbox.
	EmailVerificationToken string `bson:"email_verification_token,omitempty"`

	// EmailVerificationExpiry is when the verification token becomes invalid.
	EmailVerificationExpiry time.Time `bson:"email_verification_expiry,omitempty"`
}
