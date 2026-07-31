// Package tokenpolicy is the token-policy engine (Phase 2 of token
// governance) — the policy LAYER between a token request and issuance that
// the raw Client.AccessTokenTTL / issuer-default TTL cannot express. It
// complements the wave-1 telemetry package [domains/metering]: telemetry
// answers "which tokens are used"; this answers "which tokens may be
// issued, for how long, and in what combination".
//
// The heart is a PURE, deterministic [Evaluate] function (no I/O, no clock,
// no randomness) that maps a [PolicyInput] + the active [Policy] set onto a
// [PolicyDecision]. A [Store] supplies the active policies; a memory
// implementation lives in ./memory and rules are YAML-loadable via
// [ParseYAML].
//
// Oracle safety (AGENTS.md §3): a decision's [DenyReason] names WHICH
// dimension tripped for the METRIC + audit log ONLY. It MUST NEVER reach
// the wire — the HTTP response stays a generic invalid_scope /
// invalid_grant so an attacker cannot learn which policy blocked them.
//
// Availability: policy evaluation is a GOVERNANCE concern, not a
// credential check. A store outage FAILS OPEN (issue the token) — the same
// stance as tenant-suspension / risk-scorer (AGENTS.md §3 Fail Modes). The
// only fail-CLOSED behavior is a matched policy's explicit deny.
package tokenpolicy

import (
	"context"
	"time"
)

// Kind is the token category a policy evaluation concerns. Bounded set —
// it feeds a metric label and gates the max_refresh_depth dimension.
type Kind string

const (
	// KindAccess is an OAuth 2.0 access-token issuance.
	KindAccess Kind = "access"
	// KindRefresh is an OAuth 2.0 refresh-token rotation.
	KindRefresh Kind = "refresh"
)

// DenyReason is the bounded, oracle-SAFE reason an evaluation denied a
// token request. It is a metric label + audit detail ONLY and MUST NEVER
// reach the wire (AGENTS.md §3 oracle-leak collapse).
type DenyReason string

const (
	// DenyNone means the request is allowed.
	DenyNone DenyReason = ""
	// DenyScopeCombo means the granted scopes contain a forbidden
	// combination (block_scope_combos).
	DenyScopeCombo DenyReason = "scope_combo_blocked"
	// DenyRefreshDepth means a refresh-token family exceeded its rotation
	// cap (max_refresh_depth).
	DenyRefreshDepth DenyReason = "refresh_depth_exceeded"
	// DenyActiveSessions means the subject is at/over its concurrent
	// session cap (max_active_sessions).
	DenyActiveSessions DenyReason = "active_sessions_exceeded"
)

// Policy is one governance rule. Its SELECTOR (ClientID + Scopes) decides
// whether it applies to a request; its DIMENSIONS (zero value = unset)
// impose the constraints. Overlapping rules combine to the STRICTEST
// constraint per dimension (see [Evaluate]) so a rule can only ever tighten
// a limit, never widen it.
//
// The yaml/json tags shape both the YAML rule files ([ParseYAML]) and the
// admin governance read API — the struct carries no secret material, so it
// is safe to serialize verbatim.
type Policy struct {
	// Name is a human label for governance display + audit; not used in
	// matching.
	Name string `yaml:"name" json:"name"`

	// --- selector ---

	// ClientID restricts the rule to one client. Empty = every client (a
	// fleet-wide default rule).
	ClientID string `yaml:"client_id,omitempty" json:"client_id,omitempty"`
	// Scopes restricts the rule to requests whose granted scopes are a
	// SUPERSET of these (ALL must be present; a trailing "*" is a prefix
	// wildcard). Empty = every request.
	Scopes []string `yaml:"scopes,omitempty" json:"scopes,omitempty"`

	// --- dimensions (zero value = unset / no constraint) ---

	// MaxTTL caps the access-token lifetime DOWNWARD (never upward): the
	// effective TTL becomes min(requested, MaxTTL). When the client left
	// AccessTokenTTL unset (requested == 0) a matching MaxTTL becomes the
	// concrete ceiling — so operators MUST set MaxTTL at or below the
	// issuer's default lifetime (the engine cannot see that default).
	MaxTTL time.Duration `yaml:"max_ttl,omitempty" json:"max_ttl,omitempty"`
	// MaxRefreshDepth caps how many times a refresh-token family may rotate
	// (OAuth 2.1). A refresh request whose RefreshDepth is at/over it denies.
	MaxRefreshDepth int `yaml:"max_refresh_depth,omitempty" json:"max_refresh_depth,omitempty"`
	// MaxActiveSessions caps concurrent active sessions per subject. A
	// request whose ActiveSessions is at/over the cap denies.
	MaxActiveSessions int `yaml:"max_active_sessions,omitempty" json:"max_active_sessions,omitempty"`
	// RequireRenewAfter is the fraction (0,1] of the token TTL after which
	// the token MUST be refreshed and cannot be reused. Surfaced on the
	// decision for the resource-server / introspection layer to enforce;
	// 0 = unset.
	RequireRenewAfter float64 `yaml:"require_renew_after,omitempty" json:"require_renew_after,omitempty"`
	// BlockScopeCombos lists forbidden scope COMBINATIONS: a request whose
	// granted scopes contain ALL entries of any one inner group denies
	// (e.g. [["admin:*","openid"]] blocks minting an admin token that also
	// carries openid). Each entry supports the same trailing-"*" wildcard
	// as the selector.
	BlockScopeCombos [][]string `yaml:"block_scope_combos,omitempty" json:"block_scope_combos,omitempty"`
}

// PolicyInput is the deterministic input to [Evaluate]. Callers populate
// only the fields they know at their seam — an unknown numeric field left
// zero simply never trips its dimension.
type PolicyInput struct {
	// ClientID is the OAuth client the token is being issued to.
	ClientID string
	// Subject is the resource owner (may be empty for client_credentials).
	Subject string
	// Scopes is the FINAL granted scope set for the token.
	Scopes []string
	// Kind is the token category (max_refresh_depth applies to KindRefresh).
	Kind Kind
	// RefreshDepth is how many rotations this refresh family has already
	// performed (0 when unknown / not a refresh).
	RefreshDepth int
	// ActiveSessions is the subject's current concurrent active-session
	// count (0 when unknown).
	ActiveSessions int
	// RequestedTTL is the lifetime the issue site would use absent policy —
	// Client.AccessTokenTTL (0 = "issuer default"). Evaluate clamps it.
	RequestedTTL time.Duration
}

// PolicyDecision is the deterministic output of [Evaluate].
type PolicyDecision struct {
	// EffectiveTTL is the access-token lifetime after clamping. It is NEVER
	// greater than a positive PolicyInput.RequestedTTL (downward-only). 0
	// means "no policy TTL applied — leave the issuer default" (only when
	// RequestedTTL was 0 and no MaxTTL matched).
	EffectiveTTL time.Duration
	// Deny is true when the request violates a hard constraint. Reason
	// names WHICH — for the metric + audit ONLY, never the wire.
	Deny   bool
	Reason DenyReason
	// RenewAfter is the strictest matching RequireRenewAfter fraction
	// (0 = none) for the RS/introspection layer to enforce.
	RenewAfter float64
}

// Store is the token-policy SPI: the active policy set for evaluation plus
// the governance read API. Implementations MUST be safe for concurrent use
// — Policies is called on the token-issuance hot path (opt-in) while the
// admin API reads and dynamic updates replace the set. A memory
// implementation lives in ./memory.
type Store interface {
	// Policies returns the active policy set. Returned slices are treated
	// as READ-ONLY by callers; implementations that support dynamic updates
	// MUST swap in a fresh slice rather than mutate the returned one.
	Policies(ctx context.Context) ([]Policy, error)
}
