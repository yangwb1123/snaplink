package spi

import (
	"context"

	"github.com/snaplink/sso/shared/core"
)

// PasswordHealthChecker evaluates a plaintext password AFTER successful
// authentication and returns a non-blocking signal. Hooked into the
// password authenticator's Authenticate path — invoked only once the
// primary credential has already verified, so a membership lookup here
// poses no credential-oracle risk (the caller already proved the
// password).
//
// This SSO has no runtime register / change-password endpoint: operators
// pre-bcrypt and seed credentials, so login is the ONLY moment the server
// ever sees plaintext. That makes login the only place a strength/breach
// signal can be derived, and it must be emitted without disturbing the
// authentication outcome.
//
// Fail-open contract: a Check error is logged by the caller (or swallowed
// where no logger is reachable) and NEVER blocks login — failing closed on
// a misbehaving checker locks every user out, worse than skipping a single
// advisory. A nil checker means no check runs and there is zero overhead on
// the login path. Implementations own their state (a dictionary set, a
// bloom filter of breached hashes) and must return quickly; this runs on
// the synchronous login path.
//
// The reference [defaultimpl.DictionaryPasswordHealthChecker] does an
// offline dictionary match with no external dependency. An operator who
// wants online breach lookup (e.g. HIBP k-anonymity range queries)
// implements this interface themselves — the SDK ships no network call.
type PasswordHealthChecker interface {
	// Check evaluates the just-verified plaintext password and returns a
	// non-blocking signal, or (nil, nil) when the credential is healthy.
	// A non-nil error is advisory only: the caller treats it as fail-open
	// (no signal) and the login proceeds regardless.
	Check(ctx context.Context, password string) (*core.CredentialHealth, error)
}
