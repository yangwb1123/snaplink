package rs

import "fmt"

// Authorization helpers over validated Claims. They operate on the token's
// OWN scope claim only — no AS round-trip — so they are the RS-side
// complement of the AS's Authorizer, not a replacement for a policy engine.
// A nil *Claims never authorizes anything (fail-closed for handlers wired
// without the middleware).

// HasScope reports whether the token's scope claim contains scope exactly.
func HasScope(c *Claims, scope string) bool {
	for _, s := range c.Scopes() {
		if s == scope {
			return true
		}
	}
	return false
}

// CheckScope returns nil only when EVERY required scope is present;
// otherwise ErrInsufficientScope naming the first missing one.
func CheckScope(c *Claims, required ...string) error {
	for _, want := range required {
		if !HasScope(c, want) {
			return fmt.Errorf("%w: %s", ErrInsufficientScope, want)
		}
	}
	return nil
}

// CheckAnyScope returns nil when AT LEAST ONE of the listed scopes is
// present — the "reader or admin may pass" shape. An empty list matches
// nothing (fail-closed).
func CheckAnyScope(c *Claims, any ...string) error {
	for _, want := range any {
		if HasScope(c, want) {
			return nil
		}
	}
	return fmt.Errorf("%w: none of %v", ErrInsufficientScope, any)
}

// RequireSubject returns the token subject, or ErrSubjectMissing when the
// token has none — the guard that keeps a client_credentials (machine)
// token out of user-only endpoints.
func RequireSubject(c *Claims) (string, error) {
	if c == nil || c.Subject == "" {
		return "", ErrSubjectMissing
	}
	return c.Subject, nil
}
