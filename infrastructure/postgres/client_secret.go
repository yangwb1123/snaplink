package postgres

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// Client-secret helpers for the Postgres ClientStore. Secrets + RFC 7592
// registration access tokens are bcrypt-hashed at rest (matching the memory /
// sqlite / redis peers); already-hashed ($2 prefix) values pass through so
// re-Update is idempotent. ValidateSecret compares via shared/security.
// CompareClientSecret, so this file only needs the write-side hashing.

func isBcryptHash(s string) bool { return strings.HasPrefix(s, "$2") }

func hashClientSecret(plaintext string) (string, error) {
	h, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

// hashClientSecretField re-hashes value only when it is non-empty plaintext (a
// value already shaped like a bcrypt hash is preserved verbatim). label scopes
// the wrapped error for diagnosis.
func hashClientSecretField(value, label string) (string, error) {
	if isBcryptHash(value) || value == "" {
		return value, nil
	}
	h, err := hashClientSecret(value)
	if err != nil {
		return "", fmt.Errorf("postgres: hash %s: %w", label, err)
	}
	return h, nil
}

// generateClientSecret returns 32 bytes of base64url entropy (~256 bits),
// matching the other backends' RotateSecret output.
func generateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("postgres: rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// boolToInt encodes a Go bool as the 0/1 INTEGER the client bool columns store
// (kept as INTEGER, not BOOLEAN, so the scan path is byte-identical to the
// sqlite peer).
func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
