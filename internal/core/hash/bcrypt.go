package hash

import "golang.org/x/crypto/bcrypt"

// BcryptHasher is a Hasher implementation that uses the bcrypt algorithm.
type BcryptHasher struct {
	cost int
}

// NewBcryptHasher creates a new BcryptHasher with the given cost factor.
// Higher cost values increase hashing time and resistance to brute-force attacks.
// Pass bcrypt.DefaultCost if you don't have a specific requirement.
func NewBcryptHasher(cost int) *BcryptHasher {
	return &BcryptHasher{cost: cost}
}

// Hash generates a bcrypt hash of the given plain-text password using the configured cost.
func (h *BcryptHasher) Hash(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), h.cost)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// Verify compares a plain-text password against a bcrypt hash
// and returns true if they match.
func (h *BcryptHasher) Verify(password, hashedPassword string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password)) == nil
}
