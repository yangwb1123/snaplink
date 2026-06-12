package authenticators

import (
	"context"

	sso "github.com/snaplink/sso"
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
	// Fast-exit when no rehash machinery is wired.
	if r.Updater == nil || r.NeedsRehash == nil {
		return result, nil
	}
	needs, nhErr := r.NeedsRehash(ctx, username)
	if nhErr != nil {
		if r.Logger != nil {
			r.Logger.Error("lazy rehash: NeedsRehash failed (skipping)", "username", username, "error", nhErr)
		}
		return result, nil
	}
	if !needs {
		return result, nil
	}
	// Snapshot plaintext; goroutine captures it by value.
	pass := password
	user := username
	go func() {
		newHash, genErr := HashPassword(pass)
		if genErr != nil {
			if r.Logger != nil {
				r.Logger.Error("lazy rehash: bcrypt generate failed", "username", user, "error", genErr)
			}
			return
		}
		if upErr := r.Updater(context.Background(), user, newHash.Hash); upErr != nil {
			if r.Logger != nil {
				r.Logger.Error("lazy rehash: updater failed", "username", user, "error", upErr)
			}
		}
	}()
	return result, nil
}

// Compile-time assertion: LazyRehashVerifier satisfies PasswordVerifier.
var _ PasswordVerifier = (*LazyRehashVerifier)(nil)
