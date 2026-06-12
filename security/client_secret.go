package security

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// CompareClientSecret returns true if plaintext matches the stored value.
// When stored starts with "$2" (a bcrypt hash) it uses
// bcrypt.CompareHashAndPassword; otherwise it falls back to
// ConstantTimeStringEq for backward compatibility with plaintext secrets in
// pre-migration stores or hand-authored seeds.
//
// This is the single compare seam used by both the OAuth /token client-auth
// path (via ClientStore.ValidateSecret) and the RFC 7592 registration-access-
// token gate (authorizeRegistrationMgmt). Keeping it here means no import from
// defaultimpl into oauth/ — the caller only needs the security package.
func CompareClientSecret(stored, plaintext string) bool {
	if strings.HasPrefix(stored, "$2") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(plaintext)) == nil
	}
	// Plaintext fallback: constant-time compare so we don't introduce a
	// byte-at-a-time timing oracle on the legacy path.
	return ConstantTimeStringEq(stored, plaintext) == 1
}
