// Package conditionalaccess is the zero-trust Conditional Access Policy (CAP)
// engine: it resolves a set of operator-authored policies against a per-request
// AccessContext (a trust score, the subject's groups, a device-posture hint,
// geo, time, and the requested scopes) into an allow / deny / require-step-up
// Decision plus scope restrictions.
//
// Layering: this is a DOMAIN concern. It depends on nothing above the shared
// kernel — the trust score it consumes rides IN the AccessContext as a plain
// 0.0-1.0 float (produced upstream by the trust scorer / geo / anomaly domains
// and handed in by the caller), so the engine pulls in no cross-domain import
// and stays a pure, dependency-light policy evaluator.
//
// Fail modes (AGENTS.md §3):
//   - The policy VERDICT itself is fail-CLOSED: a policy the engine cannot
//     evaluate (a malformed condition) denies rather than being silently
//     skipped (see Decide / matchPolicy).
//   - A missing DATA SIGNAL (no trust score, a device that won't report
//     posture) is fail-OPEN on the data source: the engine substitutes a
//     conservative degraded trust value (Config.DegradedTrust, the spec's
//     "floor") and keeps evaluating rather than denying outright. Geo is
//     likewise fail-open (UX-only): an unknown country skips a geo-gated policy
//     instead of tripping a geo deny.
//
// PEP integration: the Server exposes an advisory evaluation entry point
// (Server.EvaluateConditionalAccess), a read-only admin governance view, AND —
// when Config.Enforce is set — a live gate on /auth/login (after credential
// validation, before token/session issuance) that acts on the Decision:
// VerdictDeny blocks the login, VerdictRequireStepUp routes through the SAME
// MFA orchestration a RiskScorer's RequireMFA uses (never inventing a step-up
// path the deployment hasn't already configured). Config.Enforce defaults to
// false (the historical advisory-only behavior), so wiring a store via
// WithConditionalAccess without also setting Enforce changes no live auth
// decision. A DeviceFingerprint (see devicefingerprint.go) is the engine's
// device-posture signal source, feeding AccessContext.DevicePosture the same
// way a trust.TrustScorer feeds AccessContext.TrustScore.
package conditionalaccess

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Verdict is the resolved primary outcome of a Decision. Bounded to three
// values so it is safe as a metric label (§5).
type Verdict string

const (
	// VerdictAllow permits the request (possibly with scope restrictions).
	VerdictAllow Verdict = "allow"
	// VerdictDeny blocks the request.
	VerdictDeny Verdict = "deny"
	// VerdictRequireStepUp permits only after a step-up authentication
	// (Decision.StepUpMethod names the required method, e.g. "mfa").
	VerdictRequireStepUp Verdict = "require_step_up"
)

// DevicePosture is the MDM/compliance hint for the requesting device.
type DevicePosture int

const (
	// PostureUnknown is the zero value: the device did not report posture.
	// The engine treats an unknown-posture device conservatively — it caps
	// the effective trust at Config.DegradedTrust (privacy-respecting
	// degradation, per the spec) and, for a device.managed condition, an
	// unknown device is NOT managed.
	PostureUnknown DevicePosture = iota
	// PostureManaged is an MDM-enrolled / compliant device.
	PostureManaged
	// PostureUnmanaged is a device that reported but is not managed.
	PostureUnmanaged
)

// DefaultDegradedTrust is the conservative trust value substituted when a
// signal is missing (no trust score, or a device that won't report posture).
// Matches the spec's "unreported device -> max_trust = 0.3" example. It is
// deliberately non-zero: a zero floor would make every missing-signal request
// maximally risky, which would defeat fail-open-on-data-source and turn a
// monitoring outage into a fleet-wide lockout.
const DefaultDegradedTrust = 0.3

// Config tunes the engine's fail modes.
type Config struct {
	// DegradedTrust is the trust value substituted when the trust score is
	// unknown, and the cap applied when a device won't report posture. A value
	// <= 0 or > 1 normalizes to DefaultDegradedTrust.
	DegradedTrust float64
	// DefaultDeny flips the no-policy-matched verdict from allow (the advisory
	// default, byte-compatible with an unconfigured engine) to deny (a
	// zero-trust default-deny posture). It also governs the fallback verdict
	// when the policy store is unavailable in Engine.Evaluate.
	DefaultDeny bool
	// Enforce activates LIVE enforcement at /auth/login (the PEP integration):
	// when true, a wired Server acts on Decision.Verdict — VerdictDeny blocks
	// the login, VerdictRequireStepUp routes through the configured MFA
	// step-up (only when one is wired; see the Server's login gate). The zero
	// value (false) is the historical ADVISORY-only behavior: the engine
	// still answers EvaluateConditionalAccess and serves the read-only admin
	// view, but /auth/login itself is byte-identical to a build without this
	// field set. This is deliberately independent of DefaultDeny — DefaultDeny
	// picks the verdict for a NO-MATCH/store-outage case, Enforce picks
	// whether any verdict (match or default) is ever ACTED on.
	Enforce bool
}

// degradedTrust returns the normalized floor. Kept a method so the pure Decide
// path is correct even when handed a raw (unnormalized) Config.
func (c Config) degradedTrust() float64 {
	if c.DegradedTrust <= 0 || c.DegradedTrust > 1 {
		return DefaultDegradedTrust
	}
	return c.DegradedTrust
}

// Conditions is the AND-combined predicate of a policy: every SET field must be
// satisfied for the policy to apply. A field left at its zero value is
// unconstrained (not evaluated); a Conditions with no set fields matches every
// context (a catch-all). Within the list-valued fields the members are
// OR-combined (any-of).
type Conditions struct {
	// UserMemberOf matches when the subject is in AT LEAST ONE of these groups
	// (exact, case-sensitive — group names are identifiers).
	UserMemberOf []string `yaml:"user.member_of,omitempty" json:"user_member_of,omitempty"`
	// DeviceManaged is tri-state: nil is unconstrained; true matches only a
	// PostureManaged device; false matches a PostureUnmanaged OR PostureUnknown
	// device (an unreported device is, conservatively, not managed).
	DeviceManaged *bool `yaml:"device.managed,omitempty" json:"device_managed,omitempty"`
	// RiskScore is a comparison against the derived risk (1 - effective trust),
	// e.g. "> 0.5", ">= 0.5", "< 0.3", "== 0", "!= 1". A malformed comparison
	// makes the policy un-evaluable -> fail-closed deny.
	RiskScore string `yaml:"risk_score,omitempty" json:"risk_score,omitempty"`
	// GeoIn matches when the request country (ISO 3166-1 alpha-2) is in this set
	// (case-insensitive). An unknown country never matches (geo is fail-open).
	GeoIn []string `yaml:"geo.in,omitempty" json:"geo_in,omitempty"`
	// GeoNotIn matches when the request country is NOT in this set. An unknown
	// country makes the geo condition NOT match (fail-open: an unknown geo never
	// trips a geo deny).
	GeoNotIn []string `yaml:"geo.not_in,omitempty" json:"geo_not_in,omitempty"`
	// TimeAfter / TimeBefore bound the UTC time-of-day window ("HH:MM", 24h).
	// After is inclusive, Before is exclusive; when After > Before the window
	// wraps midnight. A zero AccessContext.Now makes a time-gated policy NOT
	// match (the window can't be evaluated without a clock).
	TimeAfter  string `yaml:"time.after,omitempty" json:"time_after,omitempty"`
	TimeBefore string `yaml:"time.before,omitempty" json:"time_before,omitempty"`
}

// specificity counts the set condition fields. Used as the tie-break in
// evaluation ordering so a more-specific policy wins over a broader one at the
// same priority (most-specific-match resolution).
func (c Conditions) specificity() int {
	n := 0
	for _, set := range []bool{
		len(c.UserMemberOf) > 0,
		c.DeviceManaged != nil,
		c.RiskScore != "",
		len(c.GeoIn) > 0,
		len(c.GeoNotIn) > 0,
		c.TimeAfter != "",
		c.TimeBefore != "",
	} {
		if set {
			n++
		}
	}
	return n
}

// Actions is what a matched policy asks for. Allow/Deny/RequireStepUp resolve
// to the Decision's primary Verdict (Deny > RequireStepUp > Allow); RestrictScopes
// and Log are modifiers carried alongside the verdict.
type Actions struct {
	Allow          bool     `yaml:"allow,omitempty" json:"allow,omitempty"`
	Deny           bool     `yaml:"deny,omitempty" json:"deny,omitempty"`
	RequireStepUp  string   `yaml:"require_step_up,omitempty" json:"require_step_up,omitempty"`
	RestrictScopes []string `yaml:"restrict_scopes,omitempty" json:"restrict_scopes,omitempty"`
	Log            bool     `yaml:"log,omitempty" json:"log,omitempty"`
}

// Policy is one conditional-access rule.
type Policy struct {
	// Name is the stable identifier (unique within a store; the upsert key).
	Name string `yaml:"name" json:"name"`
	// Priority orders evaluation: HIGHER priority is evaluated FIRST. Ties break
	// on specificity (more conditions first), then Name (lexical) for
	// determinism.
	Priority int `yaml:"priority,omitempty" json:"priority,omitempty"`
	// Enabled gates the policy; a disabled policy is skipped entirely.
	Enabled bool `yaml:"enabled" json:"enabled"`
	// DryRun makes the policy report-only: a match is recorded in
	// Decision.DryRunMatches but does NOT become the enforced verdict, so an
	// operator can stage a policy before enforcing it.
	DryRun     bool       `yaml:"dry_run,omitempty" json:"dry_run,omitempty"`
	Conditions Conditions `yaml:"conditions,omitempty" json:"conditions,omitempty"`
	Actions    Actions    `yaml:"actions,omitempty" json:"actions,omitempty"`
}

// Validate rejects a structurally invalid policy: an empty name, or a
// comparison / time literal that cannot be parsed. Callers (Store.Put,
// LoadPolicies) validate at write time so malformed rules never reach the
// evaluator, but Decide is also defensive at evaluation time (fail-closed).
func (p Policy) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("conditionalaccess: policy name required")
	}
	if p.Conditions.RiskScore != "" {
		if _, _, err := parseComparison(p.Conditions.RiskScore); err != nil {
			return err
		}
	}
	for _, hhmm := range []string{p.Conditions.TimeAfter, p.Conditions.TimeBefore} {
		if hhmm == "" {
			continue
		}
		if _, err := parseHHMM(hhmm); err != nil {
			return err
		}
	}
	return nil
}

// AccessContext is the per-request evaluation input. All fields are inputs;
// evaluation mutates nothing.
type AccessContext struct {
	// TrustScore is the 0.0-1.0 zero-trust score (higher = more trustworthy),
	// consulted only when TrustScoreKnown is true; otherwise the engine
	// substitutes Config.DegradedTrust (fail-open on a missing signal).
	TrustScore      float64
	TrustScoreKnown bool
	// DevicePosture is the MDM/compliance hint (PostureUnknown -> trust capped
	// at the degraded floor).
	DevicePosture DevicePosture
	// Groups are the subject's group / role memberships (for user.member_of).
	Groups []string
	// Country is the ISO 3166-1 alpha-2 country from geo enrichment ("" =
	// unknown).
	Country string
	// Now is the evaluation time; time-of-day conditions compare its UTC
	// wall clock. A zero value disables time conditions.
	Now time.Time
	// RequestedScopes are the scopes the request asked for (carried for the
	// caller's restrict_scopes application; the engine does not gate on them).
	RequestedScopes []string
	// Subject / ClientID are advisory context for the Decision trace; they do
	// not affect the verdict.
	Subject  string
	ClientID string
}

// Decision is the engine's advisory output.
type Decision struct {
	// Verdict is the resolved primary outcome.
	Verdict Verdict
	// MatchedPolicy names the enforced policy ("" = default / no match).
	MatchedPolicy string
	// StepUpMethod is set when Verdict == VerdictRequireStepUp (e.g. "mfa").
	StepUpMethod string
	// RestrictScopes is the scope allowlist a matched restrict_scopes action
	// asks the caller to enforce (empty = no restriction).
	RestrictScopes []string
	// Log is true when a matched policy requested a log action.
	Log bool
	// Degraded is true when a signal was missing and the trust score was
	// degraded to the floor (fail-open on data source).
	Degraded bool
	// EffectiveTrust is the trust value actually used after degradation.
	EffectiveTrust float64
	// DryRunMatches lists report-only policies that matched but were not
	// enforced.
	DryRunMatches []string
	// Reasons is a human-readable evaluation trace (for audit / the admin view).
	Reasons []string
}

// Store persists conditional-access policies. Implementations MUST be safe for
// concurrent use and MUST validate on Put.
type Store interface {
	// List returns every stored policy (order unspecified; the engine sorts).
	List(ctx context.Context) ([]Policy, error)
	// Get returns the policy by name; ok is false when absent (not an error).
	Get(ctx context.Context, name string) (policy Policy, ok bool, err error)
	// Put inserts or replaces the policy keyed by Name, after Validate.
	Put(ctx context.Context, p Policy) error
	// Delete removes the policy by name. Idempotent.
	Delete(ctx context.Context, name string) error
}

// cloneStrings copies a slice so stored / returned state can't be mutated
// through an aliased backing array (matching the repo's by-value store
// contract).
func cloneStrings(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}

// contains reports exact membership (case-sensitive; group identifiers).
func contains(list []string, target string) bool {
	for _, v := range list {
		if v == target {
			return true
		}
	}
	return false
}

// containsFold reports case-insensitive membership (country codes).
func containsFold(list []string, target string) bool {
	for _, v := range list {
		if strings.EqualFold(v, target) {
			return true
		}
	}
	return false
}
