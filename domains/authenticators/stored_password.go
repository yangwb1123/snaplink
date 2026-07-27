package authenticators

import (
	"context"
	"errors"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// ErrStoredPasswordAuthFailed is returned when the username cannot be resolved
// OR the password does not match. One error for both cases — the caller must
// not distinguish (anti-enumeration).
var ErrStoredPasswordAuthFailed = errors.New("authenticators: password authentication failed")

// UserIDResolver maps a login username to the stable user ID a
// PasswordCredentialStore is keyed by — the same id the bearer's sub carries,
// so POST /me/password and login operate on one credential. A resolver
// typically looks the username up via the UserProvider (by email/external id)
// or, in the simplest deployments, returns the username unchanged.
type UserIDResolver func(ctx context.Context, username string) (userID string, err error)

// NewStoredPasswordVerifier returns a PasswordVerifier backed by a
// sso.PasswordCredentialStore. It resolves the username to a userID, then
// verifies the password against the store; on success it returns
// AuthResult{UserID, Provider: password}.
func NewStoredPasswordVerifier(store sso.PasswordCredentialStore, resolve UserIDResolver) PasswordVerifier {
	return PasswordVerifierFunc(func(ctx context.Context, username, password string) (*sso.AuthResult, error) {
		userID, err := resolve(ctx, username)
		if err != nil || userID == "" {
			_ = store.VerifyPassword(ctx, "", password) // timing parity on unknown user
			return nil, ErrStoredPasswordAuthFailed
		}
		if verr := store.VerifyPassword(ctx, userID, password); verr != nil {
			return nil, ErrStoredPasswordAuthFailed
		}
		return &sso.AuthResult{UserID: userID, Provider: MethodPassword}, nil
	})
}
