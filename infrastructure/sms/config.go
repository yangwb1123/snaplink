// Package sms is the built-in HTTP REST implementation of an SMS transport
// for one-time verification codes. It targets the well-documented, stable
// Twilio Messages API REST contract (POST .../Messages.json, HTTP Basic
// Auth, form-encoded To/From/Body) using only net/http — no vendor SDK
// dependency — so any Twilio-compatible gateway works without a code
// change. It is the default, zero-external-dependency way the runnable
// sso-server binary can actually deliver an SMS; an operator with a
// different provider can still supply their own
// domains/authenticators.SMSSender implementation via the SDK options
// instead.
package sms

import "time"

// Config configures the built-in HTTP REST SMS sender. Field-for-field
// mirror of config.SMSConfig (cmd/sso-server/serverbuildauthn translates one
// into the other at the wiring site). Kept as an independent type rather
// than importing the config package directly: config/ is a
// composition-layer package (layer rank 6 in architecture_layer_test.go)
// while infrastructure/ is rank 4, and the layer gate only allows a package
// to import its own layer or a strictly lower (more-shared) one — an
// infrastructure package importing config would be an upward edge the gate
// rejects, and the exemption list is frozen (shrink-only, no new entries).
// infrastructure/defaultimpl/emailsmtp.Config is the same split for the
// same reason.
type Config struct {
	// AccountSID is the Twilio (or Twilio-compatible) Account SID, both the
	// HTTP Basic Auth username and the path segment identifying which
	// account's Messages resource is dialed. Required.
	AccountSID string
	// AuthToken is the HTTP Basic Auth password. Required. Typically
	// injected via config/secrets.go secret:// resolution or an env
	// override at the config layer, never a plaintext YAML default —
	// mirrors emailsmtp.Config.Password.
	AuthToken string
	// FromNumber is the sending number/alphanumeric sender ID (the
	// Twilio-provisioned "From" the message is sent as). Required.
	FromNumber string
	// MessageTemplate renders the outbound body; the literal substring
	// "{code}" is replaced with the generated verification code. Empty uses
	// defaultMessageTemplate.
	MessageTemplate string
	// HTTPTimeout bounds a single outbound request (connect + read); <= 0
	// uses defaultHTTPTimeout.
	HTTPTimeout time.Duration
	// BaseURL overrides the REST API origin (scheme://host, no trailing
	// slash) — set to point at a Twilio-compatible gateway or a test
	// double. Empty uses the real Twilio API origin (defaultBaseURL).
	BaseURL string
}
