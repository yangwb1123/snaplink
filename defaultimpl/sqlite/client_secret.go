package sqlite

import (
	"strings"

	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/security"
	"golang.org/x/crypto/bcrypt"
)

// hashClientSecret hashes a plaintext client secret using the shared
// defaultimpl.BcryptCost work factor.  Only called at write time
// (create/rotate) — bcrypt is expensive and the hash includes the salt,
// so it is a one-shot operation at mutation.
func hashClientSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), defaultimpl.BcryptCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// isBcryptHash reports whether s is already a bcrypt hash.  Used at write time
// to skip re-hashing a value that arrived already hashed (e.g. an Update that
// preserved the stored hash unchanged).
func isBcryptHash(s string) bool {
	return strings.HasPrefix(s, "$2")
}

// compareClientSecret returns true if plaintext matches the stored value.
// Delegates to security.CompareClientSecret (bcrypt when stored is a hash,
// constant-time fallback for pre-migration plaintext stores).
func compareClientSecret(stored, plaintext string) bool {
	return security.CompareClientSecret(stored, plaintext)
}
