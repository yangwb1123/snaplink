package security

import (
	"context"
	"sync"
	"time"
)

// Per-account lockout — the missing defense between IP-level rate
// limiting and the underlying credential verifier. A botnet
// rotating IPs can stay under the per-IP rate-limit threshold
// while grinding one specific account at attacker-side leisure;
// per-account lockout shuts that down by tracking failures
// against the identity-being-authenticated rather than the
// caller's network address.
//
// Threat model:
//   - Distributed credential stuffing: 10K IPs each making 1
//     attempt against the same username. Per-IP limit doesn't
//     fire; per-account does (5 attempts → lockout).
//   - Targeted account harassment: an attacker locks a specific
//     user out by hammering bad credentials. Per-IP limit
//     mitigates somewhat (the attacker's IPs get rate-limited);
//     per-account adds an explicit `account_locked` signal so
//     the user / operator can spot it. Auto-unlock after the
//     lockout duration prevents permanent DoS from this vector.
//
// What this primitive intentionally does NOT do:
//   - Notify the user (email/SMS) on lockout — that's the next
//     layer up and depends on per-user contact info.
//   - Score risk based on lockout history — that's the
//     RiskScorer's job.
//   - Survive process restart in the default impl — production
//     deployments behind a load balancer should swap for a
//     shared backend (Redis / SQL) so a restart can't accidentally
//     un-lock an account.

// AccountLockout is the SPI the server consults on every login
// attempt. Implementations are responsible for:
//   - Counting consecutive failures within a sliding window.
//   - Locking the key when the counter crosses a threshold.
//   - Auto-unlocking after the lockout duration elapses.
//   - Resetting the counter on a successful authentication.
//
// The `key` is opaque to the impl — the server composes it as
// `<client_id>:<identifier>` so two different clients each
// authenticating the same identifier maintain separate lockout
// state.
//
// All methods MUST be safe for concurrent use.
type AccountLockout interface {
	// IsLocked returns whether the key is currently locked + when
	// the lock expires. Callers consult this BEFORE invoking the
	// underlying authenticator so attempts against locked
	// accounts don't even hit the credential verifier.
	IsLocked(ctx context.Context, key string) (locked bool, until time.Time, err error)

	// RegisterFailure increments the failure counter. Returns
	// (locked=true, until) if this failure crossed the threshold
	// AND the lock just engaged. Subsequent failures against an
	// already-locked key keep returning (true, until).
	RegisterFailure(ctx context.Context, key string) (locked bool, until time.Time, err error)

	// RegisterSuccess clears the failure counter so a fresh run
	// of bad attempts has to climb back to the threshold from 0.
	// Idempotent — calling on a never-failed key is a no-op.
	RegisterSuccess(ctx context.Context, key string) error
}

// Lockout-policy defaults. Conservative starting points; tune for
// the deployment's threat model + user-experience tolerance.
const (
	DefaultLockoutMaxFailures   = 5
	DefaultLockoutDuration      = 15 * time.Minute
	DefaultLockoutFailureWindow = 1 * time.Hour
)

// MemoryAccountLockout is the in-process AccountLockout. Suitable
// for single-replica deployments + tests. Multi-replica
// deployments MUST swap for a shared backend — without it, the
// counter forks per replica and attackers slip through.
//
// Implementation: per-key {failures int, firstFailureAt time,
// lockedUntil time}. The firstFailureAt is the start of the
// sliding window; if a new failure arrives AFTER firstFailureAt +
// FailureWindow, the window resets to a fresh count of 1.
type MemoryAccountLockout struct {
	MaxFailures     int
	LockoutDuration time.Duration
	FailureWindow   time.Duration

	mu      sync.Mutex
	entries map[string]*lockoutEntry
}

type lockoutEntry struct {
	failures       int
	firstFailureAt time.Time
	lockedUntil    time.Time
}

// NewMemoryAccountLockout returns a ready-to-use instance with
// `Default*` configuration. Fields are exported so callers can
// override directly after construction.
func NewMemoryAccountLockout() *MemoryAccountLockout {
	return &MemoryAccountLockout{
		MaxFailures:     DefaultLockoutMaxFailures,
		LockoutDuration: DefaultLockoutDuration,
		FailureWindow:   DefaultLockoutFailureWindow,
		entries:         make(map[string]*lockoutEntry),
	}
}

// IsLocked reports whether the key is currently locked. Auto-
// unlocks expired locks lazily — no background goroutine.
func (m *MemoryAccountLockout) IsLocked(_ context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.entries[key]
	if !ok {
		return false, time.Time{}, nil
	}
	now := time.Now()
	if e.lockedUntil.IsZero() || now.After(e.lockedUntil) {
		// Lock expired — but keep the failure counter so a
		// repeat-offender pattern is still captured. Auto-reset
		// the counter only when the failure window elapsed.
		if !e.lockedUntil.IsZero() {
			e.lockedUntil = time.Time{}
		}
		return false, time.Time{}, nil
	}
	return true, e.lockedUntil, nil
}

// RegisterFailure increments the failure counter and engages the
// lock when the threshold is crossed. See the AccountLockout
// interface for the return contract.
func (m *MemoryAccountLockout) RegisterFailure(_ context.Context, key string) (bool, time.Time, error) {
	if key == "" {
		return false, time.Time{}, nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	e, ok := m.entries[key]
	if !ok {
		e = &lockoutEntry{}
		m.entries[key] = e
	}

	// Sliding-window reset: if the first failure of the current
	// window was longer than FailureWindow ago, treat this as a
	// fresh start. Without this, an account that fails once a
	// year would slowly accumulate to lockout over a decade.
	if !e.firstFailureAt.IsZero() && now.Sub(e.firstFailureAt) > m.FailureWindow {
		e.failures = 0
		e.firstFailureAt = time.Time{}
		e.lockedUntil = time.Time{}
	}

	// An already-locked key stays locked — caller saw IsLocked=true.
	if !e.lockedUntil.IsZero() && now.Before(e.lockedUntil) {
		return true, e.lockedUntil, nil
	}

	e.failures++
	if e.firstFailureAt.IsZero() {
		e.firstFailureAt = now
	}
	if e.failures >= m.MaxFailures {
		e.lockedUntil = now.Add(m.LockoutDuration)
		return true, e.lockedUntil, nil
	}
	return false, time.Time{}, nil
}

// RegisterSuccess resets the entry for the key — both the failure
// counter and any active lock. Idempotent on missing keys.
func (m *MemoryAccountLockout) RegisterSuccess(_ context.Context, key string) error {
	if key == "" {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.entries, key)
	return nil
}

// LockoutKey extracts the identifier to use as the lockout key
// from a login request's credential map. Returns "" when no
// known identifier field is present (some authenticators carry
// the identity in non-standard fields — the server treats those
// as "lockout-unkeyable" and skips the gate entirely rather than
// erroring, so custom authenticators still work).
func LockoutKey(clientID string, credential map[string]string) string {
	if credential == nil {
		return ""
	}
	for _, field := range []string{"username", "target", "identifier", "phone", "email"} {
		if v := credential[field]; v != "" {
			return clientID + ":" + v
		}
	}
	return ""
}
