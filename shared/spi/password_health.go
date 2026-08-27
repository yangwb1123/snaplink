package spi

import (
	"context"

	"github.com/yangwb1123/snaplink/shared/core"
)

// PasswordHealthChecker evaluates a plaintext password AFTER successful
// authentication and returns a non-blocking signal. Hooked into the
// password authenticator's Authenticate path — invoked only once the
// primary credential has already verified, so a membership lookup here
// poses no credential-oracle risk (the caller already proved the
// password).
//
// The server also exposes password-setting endpoints, but this SPI is
// intentionally login-only: setting paths use PasswordPolicyValidator for
// synchronous local rules, while health remains an advisory signal after a
// successful authentication. Keeping the concerns separate avoids making a
// password write depend on an external health service.
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
// offline dictionary match with no external dependency. The stock
// implementation also provides an optional HIBP k-anonymity range checker;
// custom deployments may implement this interface for another provider.
type PasswordHealthChecker interface {
	// Check evaluates the just-verified plaintext password and returns a
	// non-blocking signal, or (nil, nil) when the credential is healthy.
	// A non-nil error is advisory only: the caller treats it as fail-open
	// (no signal) and the login proceeds regardless.
	Check(ctx context.Context, password string) (*core.CredentialHealth, error)
}
