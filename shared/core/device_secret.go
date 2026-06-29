package core

import (
	"context"
	"errors"
	"time"
)

// DeviceSecret is the OpenID Connect Native SSO 1.0 device-secret binding: a
// server-issued opaque token that lets a SECOND native app on the same device
// obtain its own tokens (via RFC 8693 token exchange with the first app's
// id_token) without re-authenticating the user. The binding ties the secret to
// the originating (subject, session, client) so an exchange can verify the
// requester holds a secret legitimately issued to that user/session.
type DeviceSecret struct {
	Secret    string    // the opaque token value (store primary key)
	Subject   string    // the user's local subject id
	SID       string    // session id; empty when no SessionManager is wired
	ClientID  string    // the client that initiated the original login
	ExpiresAt time.Time // absolute expiry
}

// IsExpired reports whether the binding has passed its expiry.
func (d *DeviceSecret) IsExpired() bool { return time.Since(d.ExpiresAt) > 0 }

// DeviceSecretStore persists Native SSO device-secret bindings. When nil (not
// wired), the whole Native SSO feature is disabled — byte-identical to a build
// without it. memory + sqlite peers ship in defaultimpl + defaultimpl/sqlite.
type DeviceSecretStore interface {
	// Issue stores a new binding (keyed by ds.Secret).
	Issue(ctx context.Context, ds *DeviceSecret) error

	// Consume atomically retrieves AND deletes the binding for secret.
	// Missing, expired, or already-consumed all return
	// ErrDeviceSecretNotFound (single response — oracle-safe; the exchange
	// handler collapses it to invalid_grant). Each successful exchange mints
	// a fresh secret, so consuming the old one stops a replayed secret.
	Consume(ctx context.Context, secret string) (*DeviceSecret, error)
}

// ErrDeviceSecretNotFound is the sentinel Consume returns when a secret is
// missing, expired, or already consumed. Callers MUST collapse all three to a
// single invalid_grant wire response.
var ErrDeviceSecretNotFound = errors.New("sso: device secret not found or expired")

// DeviceSecretRevoker is an OPTIONAL extension a DeviceSecretStore MAY also
// implement to support admin/helpdesk revocation of ALL of a user's outstanding
// Native SSO device-secret bindings — the "a user's device was lost/compromised,
// cut off Native SSO token minting NOW (don't wait the ~15min for the secrets to
// expire)" flow, completing the account-lockout toolkit alongside session/token/
// consent/MFA/password admin controls. Admin session revocation alone does NOT
// cover this: the device-secret exchange validates a (stateless) id_token, so a
// still-unexpired id_token + a live device secret can mint fresh tokens after a
// session is revoked. The admin endpoint type-asserts this; absent → 501.
// Additive — existing DeviceSecretStore implementers compile unchanged.
type DeviceSecretRevoker interface {
	// RevokeBySubject deletes every device-secret binding for subject and
	// returns the count removed. Idempotent (returns 0 when none exist).
	RevokeBySubject(ctx context.Context, subject string) (int, error)
}
