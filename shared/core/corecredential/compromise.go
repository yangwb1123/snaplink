package corecredential

import (
	"context"
	"errors"
)

// CredentialTypeJWEDecryption is the AS's JWE request-object decryption key
// (defaultjwe.RotatingJWEDecrypter). A leak lets an attacker decrypt every
// encrypted JAR/PAR request object addressed to the AS, so it is a prime
// compromise-response target — the emergency path retires the leaked key from
// BOTH the decrypt set and the published JWKS instantly (no overlap).
const CredentialTypeJWEDecryption CredentialType = "jwe_decryption"

// ErrCompromiseUnsupported is returned by the compromise path when the
// credential class's rotator cannot instantly retire its leaked secret — it
// implements CredentialRotator but NOT CompromiseRotator. Such a class can
// only be rotated on the normal overlap schedule; forcing an emergency
// retirement would leave the leaked secret verify-accepted through the overlap
// window, defeating the point, so the framework refuses rather than pretend.
var ErrCompromiseUnsupported = errors.New("sso: credential class does not support emergency compromise")

// CompromiseRotator is the OPTIONAL CredentialRotator extension for the
// emergency-compromise path. RotateCompromised mints a fresh version AND
// immediately drops the leaked one from the verify/overlap window — unlike
// Rotate, which keeps the demoted version accepted through its OverlapWindow so
// asynchronous consumers migrate without a hard cut.
//
// A rotator implements this ONLY when it can genuinely retire its previous
// secret the instant a new one is installed (e.g. an in-process key holder
// that simply forgets the old key). A rotator whose old secret must linger for
// external consumers does NOT implement it; the compromise path then returns
// ErrCompromiseUnsupported rather than silently leaving the leak accepted.
//
// Contract mirrors CredentialRotator: on error the previously-installed
// credential MUST remain installed and serving — a failed emergency rotation
// must never leave the class with zero usable credentials.
type CompromiseRotator interface {
	CredentialRotator

	// RotateCompromised mints + installs a new version and DROPS the previous
	// one immediately (no overlap acceptance). Returns the new version's
	// governance metadata (Status active, fresh Version/CreatedAt).
	RotateCompromised(ctx context.Context) (CredentialMeta, error)
}
