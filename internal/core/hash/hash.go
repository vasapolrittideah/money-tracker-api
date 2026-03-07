package hash

// Hasher defines the contract for hashing and verifying passwords.
// Implementations must provide a one-way hashing function and a constant-time
// comparison function to guard against timing attacks.
type Hasher interface {
	// Hash generates a one-way hash of the given plain-text password.
	Hash(password string) (string, error)

	// Verify reports whether the plain-text password matches the stored hash.
	Verify(password, hashedPassword string) bool
}
