package webauthn

import (
	"context"
	"time"

	gw "github.com/go-webauthn/webauthn/webauthn"
)

// User is the per-account WebAuthn state — handle + names +
// credentials registered against the account. Satisfies
// [gw.User] without re-exposing the third-party interface to
// SDK callers.
type User struct {
	Handle      []byte
	Name        string
	DisplayName string
	Credentials []gw.Credential
}

// WebAuthnID returns the user handle the authenticator binds
// credentials to.
func (u *User) WebAuthnID() []byte { return u.Handle }

// WebAuthnName returns the human-palatable username (e.g. the
// account email). Per WebAuthn §5.4.3 this is intended for display
// only — security decisions key off WebAuthnID.
func (u *User) WebAuthnName() string { return u.Name }

// WebAuthnDisplayName returns the rendered name (e.g. "Alex Müller").
func (u *User) WebAuthnDisplayName() string { return u.DisplayName }

// WebAuthnCredentials returns every credential the user has
// enrolled. The library uses this to filter `allowCredentials` on
// the next assertion challenge.
func (u *User) WebAuthnCredentials() []gw.Credential { return u.Credentials }

var _ gw.User = (*User)(nil)

// UserStore is the SPI for per-account WebAuthn state. GetByName
// returns [ErrUserUnknown] when the username is not enrolled;
// CreateUser mints a random Handle if the caller passes one
// empty.
type UserStore interface {
	GetByName(ctx context.Context, name string) (*User, error)
	CreateUser(ctx context.Context, name, displayName string) (*User, error)
	AddCredential(ctx context.Context, name string, cred *gw.Credential) error
	UpdateCredential(ctx context.Context, name string, cred *gw.Credential) error
	// RemoveCredential unbinds the credential with credentialID from the named
	// user. Idempotent: a credentialID not enrolled for the user is a no-op
	// (returns nil), so a fan-out unbind across stores needs no ownership
	// bookkeeping. Returns [ErrUserUnknown] when name is not enrolled. Backs
	// self-service passkey removal via DELETE /me/mfa/:id.
	RemoveCredential(ctx context.Context, name string, credentialID []byte) error
}

// SessionStore holds challenge + session data between Begin* and
// Finish* calls. The session ID is opaque to the store; the helper
// mints it. Put MUST honor the TTL — expired sessions are
// invalid and the corresponding Finish* call MUST fail with
// [ErrSessionExpired]. Take returns + consumes a session atomically;
// repeat calls for the same sessionID after Take return
// [ErrSessionUnknown].
type SessionStore interface {
	Put(ctx context.Context, sessionID string, data *gw.SessionData, ttl time.Duration) error
	Take(ctx context.Context, sessionID string) (*gw.SessionData, error)
}
