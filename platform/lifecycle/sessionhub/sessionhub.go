// Package sessionhub implements the "Cross-protocol Session Hub": a
// global_sid that ties together the several protocol-specific artifacts a
// single end-user login can fan out into (a core Session always; a SAML SP
// session-index row when the login went through SAML federation; more
// protocols later), plus a Coordinator that, given a global_sid, terminates
// every linked leg by COMPOSING the already-existing per-protocol logout
// mechanisms — it never reimplements OIDC Back-Channel Logout or SAML
// Single Logout.
//
// # Why this lives in domains/, not protocols/ or interfaces/
//
// This package is a pure orchestration/bookkeeping layer: it holds no
// business logic for any one protocol, only narrow interfaces the concrete
// mechanisms (protocols/oidc's back-channel fan-out, the infrastructure/saml
// nested module's IdP-initiated SLO fan-out) satisfy STRUCTURALLY. Per
// AGENTS.md §0.2 imports point one-way toward shared/core; domains/ MUST NOT
// import protocols/ or infrastructure/. Declaring [OIDCLogoutTrigger] and
// [SAMLLogoutTrigger] here — rather than importing protocols/oidc or the
// (separate-module) saml package — keeps the dependency direction intact:
// the composition root (interfaces/sso, or the operator's own forked main
// for the SAML nested module) is what supplies a concrete value for each
// interface, never this package.
//
// # Purely additive
//
// A login that never touches SAML records exactly ONE link (the core
// session leg); [Coordinator.Logout] then does exactly what a plain
// /logout already does today — destroy the core session and (if wired)
// attempt the OIDC back-channel fan-out, which is itself a no-op without a
// SubjectClientIndex. Nothing here is invoked automatically from the
// existing /logout or /end_session handlers, so their behavior is
// byte-identical whether or not this package is wired — it is a new,
// additive capability (reachable via Server.SessionHub()), not a rewrite of
// an existing one.
package sessionhub

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"
)

// GlobalSID identifies one end-user login across every protocol-specific
// record it fans out into. Opaque, unguessable (crypto/rand), and never a
// credential itself — it only indexes the LinkStore.
type GlobalSID string

// Protocol identifies which per-protocol mechanism a [LinkRecord] belongs to.
type Protocol string

const (
	// ProtocolCore is the always-present leg: the core.Session minted at
	// login (core.SessionManager.Create / CreateWithMeta).
	ProtocolCore Protocol = "core"

	// ProtocolSAML marks a login that also established a SAML federated
	// identity — either this server acted as a SAML Service Provider
	// consuming an upstream IdP's assertion (infrastructure/saml/sp), or it
	// issued an assertion to a downstream SP as a SAML Identity Provider
	// (infrastructure/saml/idp). Its presence is the gate
	// [Coordinator.Logout] uses to decide whether the SAML SLO fan-out is
	// "applicable" for this global_sid.
	ProtocolSAML Protocol = "saml"
)

// LinkRecord is one (global_sid, protocol) association: this login's
// global_sid fanned out into a record in that protocol's own mechanism,
// identified by ExternalRef (protocol-specific: a core session ID for
// ProtocolCore; a placeholder for protocols like SAML whose own fan-out is
// subject-keyed, not per-login-session-keyed).
type LinkRecord struct {
	GlobalSID GlobalSID
	Protocol  Protocol

	// ExternalRef is the protocol-specific identifier this leg is found by.
	// For ProtocolCore it is the core.Session.ID (CoreSessionTerminator.Destroy
	// takes exactly this value).
	ExternalRef string

	// Subject is the local user id this login authenticated as. Denormalized
	// onto every record (rather than stored once per global_sid) so a
	// LinkStore backend stays a flat key-value shape; every record for one
	// global_sid carries the same value.
	Subject string

	CreatedAt time.Time
}

// ErrEmptyGlobalSID is returned when a caller passes the zero-value GlobalSID
// to an operation that requires one.
var ErrEmptyGlobalSID = errors.New("sessionhub: empty global_sid")

// ErrUnknownGlobalSID is returned by Coordinator.Logout when no LinkRecord
// exists for the given global_sid (already logged out, expired, or never
// issued) — a clean, distinguishable outcome for a caller that wants to
// know whether it terminated something real.
var ErrUnknownGlobalSID = errors.New("sessionhub: unknown global_sid")

// ErrLogoutInProgress is returned by Coordinator.Logout when gsid's
// propagation is ALREADY in flight on this Coordinator — i.e. this call is a
// bounced-back re-trigger (see Coordinator's inflight guard in
// coordinator.go), not a fresh request. It is not a caller error: the
// original, still-running call owns completing the propagation exactly
// once; this is a safe, idempotent no-op signal so a future receiver wired
// to call Logout again upon observing one of the OIDC/SAML fan-outs it
// triggers cannot recurse into itself forever.
var ErrLogoutInProgress = errors.New("sessionhub: logout already in progress for this global_sid")

// globalSIDBytes matches the codebase's existing session-id entropy budget
// (infrastructure/defaultimpl/memorystoreidentity uses 32 random bytes hex-
// encoded for core.Session.ID); a global_sid is exactly as sensitive as a
// session id (it indexes the same session lifecycle), so it gets the same
// entropy floor.
const globalSIDBytes = 32

// NewGlobalSID mints a fresh, unguessable global_sid (crypto/rand, hex-
// encoded — mirrors the session-id generation convention used throughout
// the SDK's default in-memory stores).
func NewGlobalSID() GlobalSID {
	b := make([]byte, globalSIDBytes)
	_, _ = rand.Read(b)
	return GlobalSID(hex.EncodeToString(b))
}
