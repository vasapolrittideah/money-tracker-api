package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Session represents an active authentication session for an account.
// It stores the issued token pair along with device context for auditing
// and supports targeted revocation via its unique ID.
type Session struct {
	ID                 bson.ObjectID `bson:"_id,omitempty"`
	AccountID          string        `bson:"account_id"`
	AccessToken        string        `bson:"access_token"`
	RefreshToken       string        `bson:"refresh_token"`
	AccessTokenExpiry  time.Time     `bson:"access_token_expiry"`
	RefreshTokenExpiry time.Time     `bson:"refresh_token_expiry"`
	CreatedAt          time.Time     `bson:"created_at"`
	UpdatedAt          time.Time     `bson:"updated_at"`

	// IPAddress captures the client context at login time.
	IPAddress string `bson:"ip_address"`

	// UserAgent captures the client context at login time.
	UserAgent string `bson:"user_agent"`
}
