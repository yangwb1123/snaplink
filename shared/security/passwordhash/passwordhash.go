// Package passwordhash centralizes the password-hashing primitives shared by
// every PasswordCredentialStore (memory, redis, sqlite, postgres): hashing,
// verification, cost introspection, the progressive-upgrade policy, and the
// timing-equalization dummy.
//
// Versioned-format contract: a stored hash is a self-describing string.
// Today the only recognized format is bcrypt ("$2a$"/"$2b$"). NeedsRehash
// reports "below the policy target OR not a recognized format", so a future
// algorithm (argon2id, PBKDF2 for FIPS) plugs in here — and only here —
// without touching the four stores or the login path.
//
// Timing parity: the unknown-user path MUST spend the same verification
// cost as a real compare. DummyHash centralizes the dummy minting so every
// store mints byte-identical dummies and raises them to the slowest
// imported hash's cost identically.
package passwordhash

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Cost constants mirror bcrypt's; stores and policies reference these so a
// future algorithm migration changes one file, not four stores.
const (
	MinCost     = bcrypt.MinCost
	DefaultCost = bcrypt.DefaultCost
	MaxCost     = bcrypt.MaxCost
)

// DummyPassword is the fixed plaintext behind the timing-equalization dummy
// hash. It must never be a plausible real password; its only purpose is that
// bcrypt-compare against it costs the same as a real compare.
const DummyPassword = "dummy-for-timing-equalization-only"

// Hash hashes plaintext with bcrypt at cost. The format is self-describing
// ("$2a$<cost>$..."), so NeedsRehash and a future migration can read the
// algorithm + cost back off the stored string.
func Hash(plaintext string, cost int) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), cost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// IsBcrypt reports whether stored is a bcrypt hash ("$2" prefix).
func IsBcrypt(stored string) bool {
	return strings.HasPrefix(stored, "$2")
}

// Verify reports whether plaintext matches stored. Only bcrypt hashes are
// verifiable today; an unrecognized format is a mismatch (fail closed) — a
// future algorithm adds its dispatch branch here, and NeedsRehash then
// drives the login-path upgrade to it.
func Verify(stored, plaintext string) bool {
	if !IsBcrypt(stored) {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plaintext)) == nil
}

// Cost returns the bcrypt work factor of stored, and whether stored is a
// recognizable bcrypt hash. Unknown-user paths use it to raise the dummy to
// the slowest imported hash's cost.
func Cost(stored string) (int, bool) {
	if !IsBcrypt(stored) {
		return 0, false
	}
	c, err := bcrypt.Cost([]byte(stored))
	if err != nil {
		return 0, false
	}
	return c, true
}

// NeedsRehash reports whether stored is below the policy target: a bcrypt
// hash with cost < targetCost, or an unrecognized format (which cannot be
// verified under the current policy and must be upgraded on next login).
func NeedsRehash(stored string, targetCost int) bool {
	if !IsBcrypt(stored) {
		return true
	}
	c, ok := Cost(stored)
	if !ok {
		return true
	}
	return c < targetCost
}

// DummyHash mints the timing-equalization dummy at cost. Centralized so
// every store produces identical dummies and raises them identically when an
// imported hash is slower than the current dummy.
func DummyHash(cost int) ([]byte, error) {
	return bcrypt.GenerateFromPassword([]byte(DummyPassword), cost)
}
