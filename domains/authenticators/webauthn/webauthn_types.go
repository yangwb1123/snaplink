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

	// CredentialExtensions holds SDK-captured WebAuthn extension results
	// (credProps / largeBlob-support — see [CredentialExtensions]), keyed by
	// base64url(credential ID), the same encoding [MFAEnrollmentAdapter] uses
	// for its factor IDs. Nil / missing entry = not requested, or the
	// authenticator's response omitted it (unknown) — never conflated with
	// an explicit false.
	CredentialExtensions map[string]CredentialExtensions
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

// CredentialExtensions holds SDK-captured WebAuthn client-extension results
// that go-webauthn's own [gw.Credential] does not persist (its constructor,
// [gw.NewCredential], copies verified attestation/authenticator data only —
// never the raw clientExtensionResults map). Populated at FinishRegistration
// when the matching Config.Request* flag asked for the extension AND the
// client echoed a result.
//
// Every field is nil when the extension was not requested, or the
// authenticator/client omitted it from the response — "unknown", never
// conflated with an explicit false. Mirrors this package's KeyOrigin
// (OriginUnknown) unknown-vs-false convention.
type CredentialExtensions struct {
	// Discoverable reports the credProps extension's "rk" output (WebAuthn
	// Level 2): whether this credential is a client-side discoverable
	// (resident) credential, usable for passwordless / conditional-mediation
	// login (see [Helper.BeginLoginConditional]).
	Discoverable *bool

	// LargeBlobSupported reports the largeBlob extension's registration-time
	// "supported" output (WebAuthn Level 3, §10.7). Detection only — this
	// package does not read/write a largeBlob at registration; see
	// [Helper.BeginLoginLargeBlob] / [Helper.FinishLoginLargeBlob] for the
	// authentication-time read/write capability seam.
	LargeBlobSupported *bool
}

// extensionCredProps / extensionLargeBlob are the WebAuthn extension
// identifier strings (§9, §10.7). go-webauthn has no typed constants for
// these — only protocol.ExtensionAppID / ExtensionAppIDExclude exist as of
// v0.17.x — so they are defined once here rather than left as repeated
// literals (AGENTS.md §4 no-literal-leaks).
const (
	extensionCredProps = "credProps"
	extensionLargeBlob = "largeBlob"
)

// credentialExtensionSetter is an OPTIONAL UserStore capability — same
// pattern as [handleResolver] — for persisting SDK-captured extension
// metadata alongside a credential. [MemoryUserStore] implements it; a store
// that doesn't is a silent no-op at [Helper.persistCredentialExtensions]:
// Discoverable/LargeBlobSupported simply stay nil ("unknown") for that
// backend, the same safe default as never having requested the extension.
type credentialExtensionSetter interface {
	SetCredentialExtensions(ctx context.Context, name string, credentialID []byte, ext CredentialExtensions) error
}

// LargeBlobRequest configures the WebAuthn Level 3 largeBlob extension
// (§10.7) for one login ceremony via [Helper.BeginLoginLargeBlob]. Exactly
// one of Read / Write should be set — the extension is read XOR write per
// ceremony; setting both is a validation error at BeginLoginLargeBlob. The
// zero value requests neither, behaving exactly like [Helper.BeginLogin].
type LargeBlobRequest struct {
	// Read requests the authenticator return its stored largeBlob for the
	// asserted credential (surfaced in [Helper.FinishLoginLargeBlob]'s
	// returned [LargeBlobResult].Read).
	Read bool

	// Write, when non-nil, requests the authenticator store these bytes as
	// the asserted credential's largeBlob. Confirmation comes back as
	// [LargeBlobResult].Written.
	Write []byte
}

// LargeBlobResult carries the largeBlob extension's client output from
// [Helper.FinishLoginLargeBlob]. This is a documented CAPABILITY SEAM (cf.
// the identitylink package's "extension point, not built in" convention):
// nothing in this repo currently consumes a largeBlob — a future
// recovery-key / key-escrow feature can read/write through this seam
// without any further ceremony change.
type LargeBlobResult struct {
	// Read is the bytes retrieved from the authenticator, non-nil only when
	// a Read was requested and the client returned a "blob" output.
	Read []byte

	// Written reports whether a requested Write was honored; nil when no
	// Write was requested.
	Written *bool
}
