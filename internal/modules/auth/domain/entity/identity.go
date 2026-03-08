package entity

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// Identity represents an authentication method linked to an account.
// An account can have multiple identities — one for each login method,
// such as local authentication (e.g. "email", "phone") or an OAuth provider
// (e.g. "google", "facebook").
type Identity struct {
	ID          bson.ObjectID `bson:"_id,omitempty"`
	AccountID   string        `bson:"account_id"`
	Email       string        `bson:"email"`
	LastLoginAt time.Time     `bson:"last_login_at"`
	CreatedAt   time.Time     `bson:"created_at"`
	UpdatedAt   time.Time     `bson:"updated_at"`

	// ProviderID is the unique user identifier issued by the external provider.
	ProviderID string `bson:"provider_id"`

	// Provider is the name of the OAuth provider (e.g. "google", "github")
	// or the local authentication method (e.g. "email", "phone").
	Provider string `bson:"provider"`
}
