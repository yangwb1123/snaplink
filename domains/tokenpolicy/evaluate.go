package tokenpolicy

import (
	"slices"
	"strings"
	"time"
)

// Evaluate is the PURE, deterministic core of the policy engine: given the
// active policies and a request input, it returns the combined decision.
// No I/O, no clock, no randomness — so the full truth table is table-testable.
// The store-backed callers load policies then call this.
//
// Combination rule: every policy whose selector MATCHES the input
// contributes. Per dimension the STRICTEST constraint wins (smallest
// positive MaxTTL, smallest positive RequireRenewAfter) so overlapping rules
// can only ever TIGHTEN. A deny by ANY matching policy denies the whole
// request; the FIRST matching deny (in policy order, then dimension order)
// sets the reason deterministically. TTL clamping still accumulates across
// all matches even on a deny so the decision is fully populated.
func Evaluate(in PolicyInput, policies []Policy) PolicyDecision {
	d := PolicyDecision{EffectiveTTL: in.RequestedTTL}
	for i := range policies {
		p := &policies[i]
		if !matches(p, in) {
			continue
		}
		d.EffectiveTTL = clampTTL(d.EffectiveTTL, p.MaxTTL)
		d.RenewAfter = stricterRenew(d.RenewAfter, p.RequireRenewAfter)
		if !d.Deny {
			if r := denyReason(p, in); r != DenyNone {
				d.Deny = true
				d.Reason = r
			}
		}
	}
	return d
}

// matches reports whether policy p's selector applies to the request: its
// ClientID (empty = any) equals the request's, AND every selector scope is
// present in the request's granted scopes.
func matches(p *Policy, in PolicyInput) bool {
	if p.ClientID != "" && p.ClientID != in.ClientID {
		return false
	}
	for _, want := range p.Scopes {
		if !scopePresent(in.Scopes, want) {
			return false
		}
	}
	return true
}

// clampTTL applies a single MaxTTL ceiling, downward-only. An unset ceiling
// (max <= 0) leaves cur. When cur is the "issuer default" sentinel (cur <= 0)
// a positive ceiling becomes the concrete value; otherwise the ceiling only
// applies when it REDUCES cur, so a positive requested TTL is never raised.
func clampTTL(cur, max time.Duration) time.Duration {
	if max <= 0 {
		return cur
	}
	if cur <= 0 || max < cur {
		return max
	}
	return cur
}

// stricterRenew combines two require_renew fractions, keeping the STRICTER
// (smaller positive) one — a smaller fraction means the token must be
// refreshed sooner. Non-positive values are "unset".
func stricterRenew(cur, f float64) float64 {
	if f <= 0 {
		return cur
	}
	if cur <= 0 || f < cur {
		return f
	}
	return cur
}

// denyReason returns the first hard-constraint violation of policy p for the
// request, or DenyNone. Dimension order is fixed (scope combos → refresh
// depth → active sessions) so the reason is deterministic.
func denyReason(p *Policy, in PolicyInput) DenyReason {
	if violatesScopeCombos(in.Scopes, p.BlockScopeCombos) {
		return DenyScopeCombo
	}
	if p.MaxRefreshDepth > 0 && in.Kind == KindRefresh && in.RefreshDepth >= p.MaxRefreshDepth {
		return DenyRefreshDepth
	}
	if p.MaxActiveSessions > 0 && in.ActiveSessions >= p.MaxActiveSessions {
		return DenyActiveSessions
	}
	return DenyNone
}

// violatesScopeCombos reports whether the granted scopes contain ALL entries
// of any one forbidden combination. An empty combo is ignored (never a
// blanket block).
func violatesScopeCombos(scopes []string, combos [][]string) bool {
	for _, combo := range combos {
		if len(combo) > 0 && containsAll(scopes, combo) {
			return true
		}
	}
	return false
}

// containsAll reports whether every want (with trailing-"*" wildcard support)
// is present in scopes.
func containsAll(scopes, want []string) bool {
	for _, w := range want {
		if !scopePresent(scopes, w) {
			return false
		}
	}
	return true
}

// scopePresent reports whether want is in scopes. A trailing "*" makes want a
// prefix match (e.g. "admin:*" matches "admin:read"); otherwise it is exact.
func scopePresent(scopes []string, want string) bool {
	if strings.HasSuffix(want, "*") {
		prefix := strings.TrimSuffix(want, "*")
		for _, s := range scopes {
			if strings.HasPrefix(s, prefix) {
				return true
			}
		}
		return false
	}
	return slices.Contains(scopes, want)
}
