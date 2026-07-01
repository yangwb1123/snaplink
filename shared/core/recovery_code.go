package core

import "context"

// RecoveryCodeStore persists single-use MFA recovery codes. When a
// user loses their TOTP device or WebAuthn authenticator, recovery
// codes serve as the backdoor — each code can be consumed once.
//
// Codes are generated as random tokens, their hashes stored. The
// plaintext codes are shown to the user exactly once (at enrollment
// confirmation). The store only ever sees the bcrypt (or SHA-256)
// hash, so a database leak doesn't expose usable recovery codes.
type RecoveryCodeStore interface {
	// Generate creates N new recovery codes for the user, returning
	// the plaintext codes (shown to the user once). Each code's hash
	// is persisted. Previous unused codes are NOT invalidated.
	Generate(ctx context.Context, userID string, n int) (codes []string, err error)

	// Consume validates and consumes a single recovery code. Returns
	// true when the code was valid and consumed. False when the code
	// is unknown or already consumed — callers MUST NOT distinguish
	// between the two (anti-enumeration).
	Consume(ctx context.Context, userID, code string) (ok bool, err error)

	// CountRemaining returns how many unused recovery codes the user
	// still has. Used by the UI to warn users when the pool is low.
	CountRemaining(ctx context.Context, userID string) (int, error)

	// RevokeAll invalidates all remaining recovery codes for the
	// user. Used when the user regenerates codes or MFA is reset.
	RevokeAll(ctx context.Context, userID string) error
}

// RecoveryCode constants.
const (
	DefaultRecoveryCodeCount = 8   // number of codes generated per batch
	RecoveryCodeBytes        = 16  // 16 bytes → 32 hex chars per code
	RecoveryCodeAlphabet     = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // no I/O/0/1
)
