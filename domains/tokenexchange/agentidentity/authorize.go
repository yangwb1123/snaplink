package agentidentity

import (
	"errors"
	"time"
)

// ErrSessionRevoked / ErrSessionExpired are internal-only reasons
// checkSessionLive distinguishes for server-side logging; HandleGrant
// collapses BOTH (and ErrNoSuchSession) to the same wire invalid_grant —
// see grant.go's oracle-leak collapse.
var (
	ErrSessionRevoked = errors.New("agentidentity: agent session revoked")
	ErrSessionExpired = errors.New("agentidentity: agent session expired")
)

// checkSessionLive is the fail-closed liveness gate HandleGrant applies to
// every AgentSession before minting: nil (defensive — a correct Store
// never returns nil with a nil error), Revoked, or past ExpiresAt all
// deny. Pure + clock-injected (now) so the boundary is table-testable
// without a real Store or a wall-clock sleep.
func checkSessionLive(sess *AgentSession, now time.Time) error {
	if sess == nil {
		return ErrNoSuchSession
	}
	if sess.Revoked {
		return ErrSessionRevoked
	}
	if !sess.ExpiresAt.IsZero() && !now.Before(sess.ExpiresAt) {
		return ErrSessionExpired
	}
	return nil
}

// IntersectScopes returns the scopes present in EVERY supplied set,
// preserving the FIRST set's order and de-duplicated — the "never widen"
// combinator HandleGrant uses to fold Agent.AllowedScopes,
// AgentSession.GrantedScopes, and the human's live entitlement down to a
// single narrowest-common set. Pure + deterministic (no I/O), so the
// folding logic is table-testable independent of any Store. Zero sets, or
// any empty/nil set among them, narrows the result to nil — intersecting
// with an empty set is always empty.
func IntersectScopes(sets ...[]string) []string {
	if len(sets) == 0 {
		return nil
	}
	common := toScopeSet(sets[0])
	for _, s := range sets[1:] {
		next := toScopeSet(s)
		for v := range common {
			if !next[v] {
				delete(common, v)
			}
		}
	}
	seen := make(map[string]bool, len(common))
	var out []string
	for _, v := range sets[0] {
		if common[v] && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	return out
}

func toScopeSet(s []string) map[string]bool {
	m := make(map[string]bool, len(s))
	for _, v := range s {
		m[v] = true
	}
	return m
}
