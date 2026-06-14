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
func (d *DeviceSecret) IsExpired() bool { return time.Now().After(d.ExpiresAt) }

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
