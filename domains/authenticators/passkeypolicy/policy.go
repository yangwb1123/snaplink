// Package passkeypolicy implements the require-passkey enrollment-nudge
// policy: an ADVISORY decision, evaluated once per successful login, over
// whether the client should be told to prompt the user to register a
// WebAuthn passkey. It computes NO credential state itself — the caller
// (interfaces/sso) supplies the "does this user already have a passkey"
// fact (read from the wired core.MFAEnrollmentStore) and, for the
// risk-based "periodic" frequency, a derived risk score (from the wired
// trust.TrustScorer) — so this package stays a pure, dependency-light
// evaluator with zero imports beyond the stdlib, mirroring
// domains/conditionalaccess's "no cross-domain import" discipline (see that
// package's doc comment).
//
// PRECISION NOTE (read before wiring Signals.HasDiscoverableCredential): the
// field name describes the IDEAL signal — a WebAuthn credential registered
// with the credProps extension's "rk" (resident key / discoverable) output
// captured true. As of this package's introduction, this codebase's
// core.MFAEnrolledFactor carries no such per-credential Discoverable bit and
// the WebAuthn ceremony does not request/capture the credProps extension, so
// the best available caller-side proxy is coarser: "has the user registered
// ANY WebAuthn credential at all" (core.MFAEnrolledFactor.Method ==
// webauthn.MethodWebAuthn), which also counts a security key registered
// purely as a second factor (non-discoverable) as satisfying the policy.
// This package's Decide logic is written against the PRECISE concept on
// purpose: the day credProps capture lands, the caller-side computation
// becomes exact with NO change needed here or to Decide's contract.
//
// Fail-open contract (AGENTS.md §3 "Fail Modes"): Decide NEVER blocks or
// degrades a login — it only turns a UX-nudge bool on or off for an
// ALREADY-succeeded authentication. A missing/erroring risk signal degrades
// PromptPeriodic to PromptOnce behavior (see Signals.RiskKnown) rather than
// suppressing the nudge or denying anything.
//
// Recovery: this package intentionally implements NO recovery flow.
// Policy.RecoveryAllowed is advisory metadata only — see its doc comment for
// the recommended reuse of the EXISTING self-service recovery-code
// (shared/core.RecoveryCodeStore, surfaced at login as the "recovery" MFA
// method — infrastructure/defaultimpl/defaultmfa.RecoveryMFAProvider) plus
// WebAuthn re-registration (POST /me/mfa/webauthn/{begin,finish}) endpoints,
// and the passwordless-only gap that reuse does NOT close (a client with no
// password and no other primary factor who loses their sole passkey has no
// existing recovery path back to a primary login — closing that gap would
// mean accepting a recovery code as a PRIMARY authenticator, new attack
// surface deliberately out of scope for this wave).
package passkeypolicy

// PromptFrequency tunes how often Decide recommends the passkey-enrollment
// nudge once Policy.RequirePasskey is on.
type PromptFrequency string

const (
	// PromptNever suppresses the nudge outright — e.g. an operator turning on
	// RequirePasskey to stage the policy (so its config exists and is ready
	// for a future enforcement wave) before turning on the UX prompt itself.
	PromptNever PromptFrequency = "never"

	// PromptOnce nudges on EVERY login while the user has no enrolled
	// passkey. This is the default: an empty PromptFrequency normalizes to
	// this (see Policy.frequency), so a Policy built with only
	// RequirePasskey set behaves as "once".
	PromptOnce PromptFrequency = "once"

	// PromptPeriodic layers a risk-based cadence on top of PromptOnce: a
	// HIGH-risk login always nudges (risk >= HighRiskThreshold), a LOW-risk
	// login is throttled (no nudge — the "periodic" part), and an UNKNOWN
	// risk (no trust.TrustScorer wired, or it errored) degrades to PromptOnce
	// behavior — fail-open toward MORE nudging, never less, and never toward
	// blocking the login.
	PromptPeriodic PromptFrequency = "periodic"
)

// Valid reports whether f is one of the three recognized frequencies. It
// validates an EXPLICIT value only (config / admin input) — the empty zero
// value is not itself "valid" by this method; unset-vs-invalid is instead
// resolved by frequency()'s "unset = once" default, so a genuine typo (e.g.
// "onec") can be rejected loudly by a caller (see cmd wiring) instead of
// silently behaving like "once".
func (f PromptFrequency) Valid() bool {
	switch f {
	case PromptNever, PromptOnce, PromptPeriodic:
		return true
	}
	return false
}

// HighRiskThreshold is the derived-risk floor (1 - trust score) at or above
// which PromptPeriodic nudges unconditionally. Named + documented rather
// than an inline magic number, mirroring
// domains/conditionalaccess.DefaultDegradedTrust's precedent.
const HighRiskThreshold = 0.5

// Policy is the require-passkey governance policy — mirrors
// config.WebAuthnConfig's passkey_policy YAML block 1:1
// (require_passkey / passkey_prompt_frequency / passkey_recovery_allowed).
type Policy struct {
	// RequirePasskey is the master switch. False (the zero value) makes
	// Decide always return false regardless of every other field — a
	// complete no-op, byte-identical to a build without this feature.
	RequirePasskey bool

	// PromptFrequency selects the cadence (see the PromptXxx constants). The
	// zero value ("") normalizes to PromptOnce.
	PromptFrequency PromptFrequency

	// RecoveryAllowed is advisory metadata a caller MAY echo alongside the
	// nudge signal so client UI knows whether to also offer a "lost your
	// passkey?" affordance. Decide does not read this field — it only gates
	// whether ANY nudge is computed at all; RecoveryAllowed governs nothing
	// about credential verification (this package implements no recovery
	// flow — see the package doc's recommended-reuse note).
	RecoveryAllowed bool
}

// frequency normalizes an unset/invalid PromptFrequency to PromptOnce — the
// safe default for "operator turned on RequirePasskey but didn't say how
// often to nudge" is "keep asking every login", not "never ask" (an unset
// frequency must not silently suppress the very feature the operator just
// turned on).
func (p Policy) frequency() PromptFrequency {
	if p.PromptFrequency.Valid() {
		return p.PromptFrequency
	}
	return PromptOnce
}

// Signals is the per-login input Decide evaluates.
type Signals struct {
	// HasDiscoverableCredential reports whether the just-authenticated user
	// already satisfies the require-passkey policy. See the package doc's
	// PRECISION NOTE: absent credProps capture in a given build, callers
	// compute this as "has ANY registered WebAuthn credential" rather than
	// the stricter "has a discoverable/resident-key credential" — Decide's
	// contract is unaffected either way. Decide never nudges a user for whom
	// this is true.
	HasDiscoverableCredential bool

	// RiskScore is the derived risk (1 - trust score, so 0 = fully trusted, 1
	// = maximally suspicious) for this login, consulted ONLY under
	// PromptPeriodic. Meaningless when RiskKnown is false.
	RiskScore float64

	// RiskKnown is false when no trust.TrustScorer was wired, or it errored —
	// Decide then treats PromptPeriodic identically to PromptOnce (fail-open:
	// absence of a risk signal means "keep nudging", never "stop nudging").
	RiskKnown bool
}

// Decide reports whether THIS login should carry the passkey-enrollment
// nudge signal. Purely advisory: the caller folds a true result into the
// login response as an extra field (see interfaces/sso's
// applyPasskeyPolicySignal) — it NEVER blocks or degrades the credential
// decision that already succeeded, matching the fail-open UX-nudge class of
// signal this codebase already uses for AuthResult.CredentialHealth.
func Decide(p Policy, s Signals) bool {
	if !p.RequirePasskey || s.HasDiscoverableCredential {
		return false
	}
	switch p.frequency() {
	case PromptNever:
		return false
	case PromptPeriodic:
		if !s.RiskKnown {
			return true // degrade to PromptOnce behavior (fail-open toward nudging)
		}
		return s.RiskScore >= HighRiskThreshold
	default: // PromptOnce
		return true
	}
}
