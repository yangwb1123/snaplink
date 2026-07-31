package oauthvalidate

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

// PathRegister is the RFC 7591 Dynamic Client Registration endpoint.
const PathRegister = "/register"

// PathRegisterByID is the RFC 7592 Dynamic Client Management endpoint —
// GET/PUT/DELETE for an individual registered client. Authorized by
// the registration_access_token issued at /register time.
const PathRegisterByID = "/register/:client_id"

// DCRPolicy controls how the registration endpoint behaves.
// Defaults are conservative: opt-in via WithDynamicClientRegistration
// and require an initial access token unless the operator explicitly
// allows open registration.
//
// InitialAccessToken, when non-empty, is the bearer the registration
// endpoint expects in the Authorization header. Operators distribute
// it out-of-band to clients allowed to register; a missing or
// mismatched bearer returns 401 invalid_token. Empty value combined
// with AllowOpenRegistration=true disables the gate (any caller may
// register — production deployments SHOULD NOT do this).
type DCRPolicy struct {
	InitialAccessToken    string
	AllowOpenRegistration bool

	// RotateRegistrationAccessToken, when true, mints a FRESH
	// registration_access_token on every successful PUT /register/:id and
	// returns it in the response (the prior token stops working). RFC 7592
	// §3.2 permits but does not mandate rotation; it limits the blast radius
	// of a leaked RAT. Default false preserves the prior behavior (the RAT is
	// stable across updates) byte-identically — enabling it is a behavior
	// change a managing client must handle (capture the new token each PUT).
	RotateRegistrationAccessToken bool
	// RegistrationAccessTokenOverlap keeps the credential used for a
	// successful rotation valid long enough to retry a lost PUT response.
	// Non-positive values use a conservative five-minute overlap.
	RegistrationAccessTokenOverlap time.Duration

	// DefaultActive controls the Active field on newly-registered
	// clients. Most deployments want true so clients work
	// immediately; security-conscious deployments may prefer false
	// so an operator approves each registration manually.
	DefaultActive bool

	// DefaultTokenStrategy stamps the new client's TokenStrategy
	// when the registration request doesn't specify one. Empty
	// inherits the server default (the runtime resolver in
	// issuerForClient picks it up).
	DefaultTokenStrategy string

	// AllowedAuthenticators, when non-empty, restricts the
	// AllowedAuthenticators field on newly-registered clients to
	// this whitelist — registrations that request anything outside
	// it are rejected with invalid_client_metadata.
	AllowedAuthenticators []string
}

// ErrDCRBadMetadata indicates the client metadata failed validation.
// Mapped to 400 invalid_client_metadata per RFC 7591 §3.2.2.
var ErrDCRBadMetadata = errors.New("sso: invalid client metadata")

// Registration-specific stable error codes per RFC 7591 §3.2.2.
const (
	ErrInvalidClientMetadata = "invalid_client_metadata"
	ErrRegistrationDisabled  = "registration_not_configured"
)

// DCR audit-metadata keys + values for the EventClientRegistered lifecycle
// event. MetaKeyDCRMethod records HOW the registration was authorized so a
// SIEM can separate operator-gated registrations from open ones; these are
// internal audit signals, not wire values.
const (
	MetaKeyDCRMethod = "registration_method"

	DCRMethodInitialAccessToken = "initial_access_token"
	DCRMethodOpen               = "open"
)

// GenerateClientID mints a base32 client identifier — short enough
// for log lines but high-entropy enough for an unguessable
// registration. 18 bytes / 144 bits beats a 128-bit floor while
// keeping the encoded length at 29 chars (no padding).
func GenerateClientID() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// GenerateClientSecret mints a 32-byte (256-bit) base64url secret —
// the same shape the admin RotateSecret RPC uses elsewhere in this
// codebase.
func GenerateClientSecret() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
