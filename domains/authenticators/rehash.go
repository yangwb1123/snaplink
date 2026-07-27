package authenticators

import (
	"context"

	sso "github.com/yangwb1123/snaplink/interfaces/sso"
)

// LazyRehashVerifier wraps an underlying PasswordVerifier. On a successful
// authentication, if the stored hash is NOT already bcrypt (i.e. it was
// imported from a legacy IdP in argon2id / PBKDF2 format), it transparently
// re-hashes the plaintext as bcrypt and calls Updater to persist the new hash.
//
// This lets migrated users authenticate on their first post-migration login
// without a forced password reset, while silently upgrading their stored hash
// to the canonical bcrypt format that the rest of the server uses.
//
// Design constraints:
//   - The re-hash is fire-and-forget: a slow or failing DB write MUST NOT
//     block the auth response. Auth succeeds even if Updater returns an error.
//   - NeedsRehash returning an error is treated as "no rehash needed" (fail-open),
//     so an outage in the user-attribute store does not degrade login.
//   - Logger.Error is called for both NeedsRehash and Updater errors, giving
//     operators visibility without changing the login outcome.
type LazyRehashVerifier struct {
	// Underlying is the real PasswordVerifier (e.g. the bcrypt verifier seeded
	// from YAML or a multi-hash verifier that knows all imported formats).
	Underlying PasswordVerifier

	// NeedsRehash reports whether the stored hash for username needs upgrading.
	// Returning (true, nil) triggers a bcrypt re-hash. Any error is treated as
	// (false, ...) — fail-open.
	NeedsRehash func(ctx context.Context, username string) (bool, error)

	// Updater stores the new bcrypt hash for username. Called in a goroutine;
	// errors are logged but never surface to the caller. Nil disables rehashing
	// (NeedsRehash is never consulted).
	Updater func(ctx context.Context, username, newBcryptHash string) error

	// Logger is optional. When set, NeedsRehash and Updater errors are logged
	// at Error level. Nil = silent.
	Logger interface{ Error(string, ...any) }
}

// Verify implements PasswordVerifier. It delegates to Underlying, and on
// success asynchronously upgrades the hash if NeedsRehash reports true.
func (r *LazyRehashVerifier) Verify(ctx context.Context, username, password string) (*sso.AuthResult, error) {
	result, err := r.Underlying.Verify(ctx, username, password)
	if err != nil {
		return nil, err
	}
	if !r.needsLazyRehash(ctx, username) {
		return result, nil
	}
	go r.rehashPassword(username, password)
	return result, nil
}

func (r *LazyRehashVerifier) needsLazyRehash(ctx context.Context, username string) bool {
	if r.Updater == nil || r.NeedsRehash == nil {
		return false
	}
	needs, err := r.NeedsRehash(ctx, username)
	if err != nil {
		r.logLazyRehashFailure(
			"lazy rehash: NeedsRehash failed (skipping)", username, "error", err,
		)
		return false
	}
	return needs
}

func (r *LazyRehashVerifier) rehashPassword(username, password string) {
	// Operator-supplied persistence runs detached; contain its panic so a
	// best-effort credential upgrade cannot crash the process.
	defer r.recoverLazyRehashPanic(username)
	newHash, err := HashPassword(password)
	if err != nil {
		r.logLazyRehashFailure(
			"lazy rehash: bcrypt generate failed", username, "error", err,
		)
		return
	}
	if err := r.Updater(context.Background(), username, newHash.Hash); err != nil {
		r.logLazyRehashFailure("lazy rehash: updater failed", username, "error", err)
	}
}

func (r *LazyRehashVerifier) recoverLazyRehashPanic(username string) {
	if rec := recover(); rec != nil {
		r.logLazyRehashFailure("lazy rehash: panic recovered", username, "panic", rec)
	}
}

func (r *LazyRehashVerifier) logLazyRehashFailure(message, username, key string, value any) {
	if r.Logger == nil {
		return
	}
	r.Logger.Error(message, "username", username, key, value)
}

// Compile-time assertion: LazyRehashVerifier satisfies PasswordVerifier.
var _ PasswordVerifier = (*LazyRehashVerifier)(nil)
