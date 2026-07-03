// Package corecredential is the dependency-free kernel for the unified
// credential-rotation framework: the credential-type/status vocabulary, the
// per-version governance metadata record, and the rotation SPIs
// (CredentialStatusStore + CredentialRotator).
//
// It lives as a leaf under shared/core (the parent directory's file budget is
// frozen — same split pattern as shared/security/securityverify) and, like
// core itself, imports NOTHING outside the standard library so every layer may
// depend on it. Secret MATERIAL never passes through this package: rotators
// install new secrets into their own backends; only metadata crosses here.
package corecredential

import (
	"errors"
	"time"
)

// CredentialType identifies one rotatable credential class managed by the
// rotation framework. The set is open — each subsystem that plugs a
// CredentialRotator into the registry declares its own constant here so the
// admin inventory and metrics use one stable, bounded vocabulary.
type CredentialType string

// CredentialTypeWebhookHMAC is the outbound webhook payload-signing HMAC
// secret (securityverify.SignWebhookPayload / RotatingWebhookSecret).
const CredentialTypeWebhookHMAC CredentialType = "webhook_hmac"

// CredentialStatus is the lifecycle state of ONE credential version.
type CredentialStatus string

const (
	// CredentialStatusActive: the version currently used to SIGN/issue.
	CredentialStatusActive CredentialStatus = "active"
	// CredentialStatusRetiring: demoted by a rotation but still ACCEPTED
	// (verify-only) until its NotAfter — the overlap window that lets
	// asynchronous consumers migrate without a hard cut.
	CredentialStatusRetiring CredentialStatus = "retiring"
	// CredentialStatusRetired: past its overlap window; no longer accepted.
	CredentialStatusRetired CredentialStatus = "retired"
	// CredentialStatusCompromised: revoked out-of-band before its natural
	// retirement (operator-declared leak). Never accepted.
	CredentialStatusCompromised CredentialStatus = "compromised"
)

var (
	// ErrCredentialNotFound is returned by CredentialStatusStore lookups for
	// an unknown (type, id) pair.
	ErrCredentialNotFound = errors.New("sso: credential not found")

	// ErrNoActiveCredential reports the state the rotation framework must
	// never reach: a credential class with zero usable versions installed
	// (e.g. a zero-value secret holder that was never seeded). Rotators keep
	// the previous version serving when minting a replacement fails, so this
	// only surfaces on construction/wiring mistakes.
	ErrNoActiveCredential = errors.New("sso: no active credential")
)

// CredentialMeta is the governance metadata of ONE credential version. It
// NEVER carries secret material — it is safe to persist, log, and return from
// the admin inventory endpoint.
type CredentialMeta struct {
	// ID names this version (a kid or a synthetic "type/vN" handle). Unique
	// within Type; never derived from the secret bytes.
	ID string `json:"id"`

	Type    CredentialType `json:"type"`
	Version int            `json:"version"`

	Status CredentialStatus `json:"status"`

	CreatedAt time.Time `json:"created_at"`

	// NotAfter is when a retiring version stops being accepted (end of the
	// overlap window). Zero for the active version (no scheduled end).
	NotAfter time.Time `json:"not_after,omitzero"`

	// Algorithm is the credential's cryptographic algorithm ("HMAC-SHA256",
	// "EdDSA", ...). Informational; empty when not applicable.
	Algorithm string `json:"algorithm,omitempty"`
}
