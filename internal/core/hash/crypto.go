package hash

import (
	"crypto/sha256"
	"encoding/hex"
)

// SHA256Hasher is a Hasher implementation that uses SHA-256.
// It is intended for high-entropy secrets such as tokens and API keys,
// where bcrypt's slow KDF and 72-byte truncation would be incorrect.
type SHA256Hasher struct{}

// NewSHA256Hasher creates a new SHA256Hasher.
func NewSHA256Hasher() Hasher {
	return &SHA256Hasher{}
}

// Hash returns a hex-encoded SHA-256 digest of the given input.
// It never returns an error; the second return value exists only to
// satisfy the Hasher interface.
func (h *SHA256Hasher) Hash(value string) (string, error) {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:]), nil
}

// Verify reports whether the plain-text value matches the stored SHA-256 hash.
func (h *SHA256Hasher) Verify(value, hashedValue string) bool {
	hashed, _ := h.Hash(value)
	return hashed == hashedValue
}
