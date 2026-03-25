package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// PasswordReset represents a password reset request issued to an account.
// It holds a unique JWT ID (JTI) to identify the reset token, tracks whether
// the token has already been used, and enforces expiry via ExpiresAt.
type PasswordReset struct {
	ID        bson.ObjectID `bson:"_id,omitempty"`
	AccountID string        `bson:"account_id"`
	JTI       string        `bson:"jti"`
	Used      bool          `bson:"used"`
	ExpiresAt time.Time     `bson:"expires_at"`
	CreatedAt time.Time     `bson:"created_at"`
	UpdatedAt time.Time     `bson:"updated_at"`
}
