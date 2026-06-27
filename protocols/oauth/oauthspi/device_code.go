package oauthspi

import (
	"context"
	"errors"
	"time"
)

// DeviceCode is the server-side record for one OAuth 2.0 device
// authorization (RFC 8628) flow. It binds a long device_code (used
// by the device for backchannel polling) to a short user_code (the
// human-friendly string the user types on a second device).
//
// State machine:
//   - pending  → user hasn't acted yet; poll returns authorization_pending
//   - approved → user verified user_code + authenticated; poll succeeds
//   - denied   → user explicitly rejected; poll returns access_denied
//   - expired  → ExpiresAt passed; poll returns expired_token
//
// LastPoll + Interval enforce the RFC's slow_down anti-thrash rule:
// when a device polls faster than Interval, the server returns
// slow_down and the device MUST bump its local interval by 5 seconds.
type DeviceCode struct {
	DeviceCode string
	UserCode   string
	ClientID   string
	Scopes     []string
	Nonce      string
	UserID     string            // populated after Approve
	Provider   string            // authenticator used at approval
	Attributes map[string]string // user attributes at approval
	Approved   bool
	Denied     bool
	LastPoll   time.Time
	Interval   time.Duration // minimum poll interval
	Resources  []string      // RFC 8707 resource indicators
	ExpiresAt  time.Time
}

// IsExpired reports whether the device code's lifetime has elapsed.
func (d *DeviceCode) IsExpired() bool {
	return time.Now().After(d.ExpiresAt)
}

// DeviceCodeStore persists OAuth 2.0 device authorization codes
// (RFC 8628). The store is queried by BOTH device_code (the
// backchannel poll path) AND user_code (the user-facing approval
// path), so backends need indexes on both columns.
//
// Single-use is enforced via Delete (called by the token endpoint
// after a successful exchange); the alternative of Approve-then-poll
// is intentional — the user can't pre-approve a code that doesn't
// exist yet, and the device can't poll a code it didn't request.
type DeviceCodeStore interface {
	// Issue persists a new device code in the pending state.
	Issue(ctx context.Context, dc *DeviceCode) error

	// GetByDeviceCode looks up a code by its device_code. Returns
	// ErrDeviceCodeNotFound for unknown / expired codes.
	GetByDeviceCode(ctx context.Context, deviceCode string) (*DeviceCode, error)

	// GetByUserCode looks up a code by its user-facing user_code.
	// Same ErrDeviceCodeNotFound semantics.
	GetByUserCode(ctx context.Context, userCode string) (*DeviceCode, error)

	// Approve marks the code as approved with the supplied user
	// identity. Server-side projection of "the user verified the
	// user_code on their browser, here's who they are."
	Approve(ctx context.Context, userCode, userID, provider string, attributes map[string]string) error

	// Deny marks the code as explicitly denied.
	Deny(ctx context.Context, userCode string) error

	// UpdateLastPoll records the most recent poll attempt for
	// slow_down enforcement.
	UpdateLastPoll(ctx context.Context, deviceCode string, t time.Time) error

	// Delete removes a code (after successful token exchange OR
	// when garbage-collecting an expired entry).
	Delete(ctx context.Context, deviceCode string) error

	// ConsumeIfApproved ATOMICALLY deletes and returns the code IFF it is
	// currently approved, so of N concurrent token-exchange polls of one
	// approved device_code exactly ONE wins (gets the record); the rest get
	// ErrDeviceCodeNotFound. A pending/denied/unknown/expired code returns
	// ErrDeviceCodeNotFound WITHOUT consuming. The token endpoint calls this as
	// the single-use claim before minting, so one approved code can never mint
	// two token sets (RFC 8628 single-use, race-safe across replicas).
	ConsumeIfApproved(ctx context.Context, deviceCode string) (*DeviceCode, error)
}

// ErrDeviceCodeNotFound is returned by store lookups when the code
// is unknown, expired, or already consumed. Indistinguishable so
// the token endpoint maps to expired_token without leaking which
// case applied.
var ErrDeviceCodeNotFound = errors.New("sso: device code not found or expired")
