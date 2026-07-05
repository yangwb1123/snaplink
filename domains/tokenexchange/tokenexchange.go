// Package tokenexchange is the RFC 8693 token-exchange hop-authorization
// layer — the policy SEAM between "this exchange request is well-formed and
// within scope/target/actor-chain limits" (enforced unconditionally by
// internal/handler/tokengrant) and "this specific delegation is one the
// operator wants to allow". It complements the built-in, always-on defenses
// (act-chain depth cap, cycle detection, chain-lifetime TTL) with an OPTIONAL
// business-rule gate: an operator who knows their own topology (e.g. "service
// A may never act on behalf of service B") can block a specific hop without
// forking the grant handler.
//
// The heart is [Policy], a single-method SPI HandleTokenExchangeGrant
// consults (when wired) once per exchange, after the hop's subject/actor/
// scopes/resources are all resolved and before anything is minted. A
// reference in-memory implementation ([domains/tokenexchange/memory]) matches
// a [Hop] against an ordered []Rule list.
//
// Fail-closed (AGENTS.md §3): a wired Policy that ERRORS is treated as a
// deny, and HandleTokenExchangeGrant collapses the denial to the SAME
// invalid_grant every other token-exchange failure returns (oracle-leak
// collapse) — the reason never reaches the wire. Nil (the default, no Policy
// wired) is a no-op: every hop is allowed, byte-identical to a build without
// this feature.
package tokenexchange

import "context"

// Hop describes one RFC 8693 token-exchange request a [Policy] is asked to
// allow or deny — the caller-controlled "who is delegating to whom"
// dimension that request-type/scope/resource validation doesn't cover.
type Hop struct {
	// SubjectID is the resolved subject_token principal (the identity being
	// acted upon / delegated for).
	SubjectID string
	// ActorSubject is the actor_token's subject — the identity requesting to
	// act on SubjectID's behalf. Empty when the exchange carries no
	// actor_token (a plain re-issuance, not a delegation).
	ActorSubject string
	// ClientID is the downstream OAuth client performing the exchange (the
	// caller authenticated at /token).
	ClientID string
	// RequestedTokenType is the RFC 8693 §2.1 requested_token_type, or ""
	// when the caller didn't specify one (defaults to access_token).
	RequestedTokenType string
	// Scopes is the FINAL narrowed scope set the exchanged token would carry.
	Scopes []string
	// Resources is the FINAL merged resource/audience target list.
	Resources []string
}

// Policy is the token-exchange hop-authorization SPI. Nil (unwired) is a
// no-op — HandleTokenExchangeGrant never calls a nil Policy, so every hop is
// allowed, exactly as before this feature existed.
type Policy interface {
	// Allow reports whether hop may proceed. An error is treated as a deny
	// (fail-closed, AGENTS.md §3) — this SPI exists specifically to let an
	// operator BLOCK delegations, so silently allowing on an evaluation
	// error would defeat its purpose.
	Allow(ctx context.Context, hop Hop) (bool, error)
}

// Rule is one static allow/deny entry a [Rule]-driven Policy (e.g.
// [domains/tokenexchange/memory].Store) matches a Hop against. An empty
// field on a dimension means "any" (a wildcard on that dimension only);
// every non-empty field must match for the Rule to apply.
type Rule struct {
	// Name is a human label for admin display / audit; not used in matching.
	Name string
	// SubjectID restricts the rule to one subject principal. Empty = any.
	SubjectID string
	// ActorSubject restricts the rule to one actor principal. Empty = any
	// (including hops with no actor_token at all).
	ActorSubject string
	// ClientID restricts the rule to one downstream client. Empty = any.
	ClientID string
	// Deny is true when a match should REJECT the hop; false means a match
	// ALLOWS it (short-circuiting any later, less specific rule).
	Deny bool
}

// Evaluate is the PURE, deterministic core of the reference rule engine:
// the FIRST Rule (in order) whose non-empty fields all match hop decides the
// outcome. No matching rule falls back to defaultAllow. No I/O, no clock —
// so the full truth table is table-testable independent of any Store.
func Evaluate(hop Hop, rules []Rule, defaultAllow bool) bool {
	for _, r := range rules {
		if ruleMatches(r, hop) {
			return !r.Deny
		}
	}
	return defaultAllow
}

// ruleMatches reports whether every non-empty field of r matches hop.
func ruleMatches(r Rule, hop Hop) bool {
	if r.SubjectID != "" && r.SubjectID != hop.SubjectID {
		return false
	}
	if r.ActorSubject != "" && r.ActorSubject != hop.ActorSubject {
		return false
	}
	if r.ClientID != "" && r.ClientID != hop.ClientID {
		return false
	}
	return true
}
