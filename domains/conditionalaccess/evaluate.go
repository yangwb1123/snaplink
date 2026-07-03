package conditionalaccess

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Reason strings recorded in Decision.Reasons — stable enough to grep in an
// audit trail without being a wire contract.
const (
	reasonDegraded         = "trust degraded: a signal was missing or a device did not report posture"
	reasonDefaultAllow     = "no policy matched: default allow"
	reasonDefaultDeny      = "no policy matched: default deny"
	reasonStoreUnavailable = "policy store unavailable: fell back to the configured default verdict"
)

// Engine binds a policy Store to a Config and is the stateful entry point the
// server calls. The decision logic itself lives in the pure Decide function so
// it can be exhaustively tested without a store.
type Engine struct {
	store Store
	cfg   Config
}

// NewEngine constructs an Engine over the given store and config.
func NewEngine(store Store, cfg Config) *Engine {
	return &Engine{store: store, cfg: cfg}
}

// Config returns the engine's configuration (for the admin governance view).
func (e *Engine) Config() Config { return e.cfg }

// Evaluate fetches the current policy set and resolves it against ac. A store
// error is a DATA-SOURCE degradation, not a policy verdict: the engine returns
// the configured default verdict (so a DefaultDeny operator still fails closed,
// a default-allow one fails open) marked Degraded, plus the error for the
// caller to log — it does NOT deny every request while the store is
// unreachable.
func (e *Engine) Evaluate(ctx context.Context, ac AccessContext) (Decision, error) {
	policies, err := e.store.List(ctx)
	if err != nil {
		dec := applyDefault(e.cfg, Decision{Degraded: true, Reasons: []string{reasonStoreUnavailable}})
		return dec, err
	}
	return Decide(e.cfg, policies, ac), nil
}

// Decide is the pure decision core: given a config, a policy set, and an access
// context it returns the advisory Decision with no I/O and no side effects.
//
// Resolution: enabled policies are ordered by priority (desc), then specificity
// (desc), then name (asc); the FIRST non-dry-run policy that matches produces
// the enforced verdict (report-only matches encountered first are collected in
// DryRunMatches). A policy that cannot be evaluated (a malformed condition)
// fails CLOSED — it denies rather than being skipped. When no policy matches,
// the configured default (allow, or deny when Config.DefaultDeny) applies.
func Decide(cfg Config, policies []Policy, ac AccessContext) Decision {
	eff, degraded := degradeTrust(cfg, ac)
	risk := 1 - eff
	dec := Decision{EffectiveTrust: eff, Degraded: degraded}
	if degraded {
		dec.Reasons = append(dec.Reasons, reasonDegraded)
	}
	for _, p := range sortedPolicies(policies) {
		matched, err := matchPolicy(p.Conditions, ac, risk)
		if err != nil {
			return denyOnError(dec, p.Name, err)
		}
		if !matched {
			continue
		}
		if p.DryRun {
			dec.DryRunMatches = append(dec.DryRunMatches, p.Name)
			continue
		}
		return applyActions(dec, p)
	}
	return applyDefault(cfg, dec)
}

// degradeTrust computes the effective trust after fail-open-on-data-source
// degradation and reports whether any degradation occurred.
func degradeTrust(cfg Config, ac AccessContext) (float64, bool) {
	floor := cfg.degradedTrust()
	eff := ac.TrustScore
	degraded := false
	if !ac.TrustScoreKnown {
		eff = floor
		degraded = true
	}
	if ac.DevicePosture == PostureUnknown && eff > floor {
		eff = floor
		degraded = true
	}
	return clamp01(eff), degraded
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

// sortedPolicies returns the enabled policies in evaluation order.
func sortedPolicies(policies []Policy) []Policy {
	out := make([]Policy, 0, len(policies))
	for _, p := range policies {
		if p.Enabled {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return lessPolicy(out[i], out[j])
	})
	return out
}

// lessPolicy orders by priority desc, then specificity desc, then name asc.
func lessPolicy(a, b Policy) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	sa, sb := a.Conditions.specificity(), b.Conditions.specificity()
	if sa != sb {
		return sa > sb
	}
	return a.Name < b.Name
}

// applyActions builds the enforced Decision from a matched policy's actions.
// Deny beats require_step_up beats allow; restrict_scopes and log ride along.
func applyActions(dec Decision, p Policy) Decision {
	dec.MatchedPolicy = p.Name
	dec.Log = p.Actions.Log
	dec.RestrictScopes = cloneStrings(p.Actions.RestrictScopes)
	switch {
	case p.Actions.Deny:
		dec.Verdict = VerdictDeny
	case p.Actions.RequireStepUp != "":
		dec.Verdict = VerdictRequireStepUp
		dec.StepUpMethod = p.Actions.RequireStepUp
	default:
		dec.Verdict = VerdictAllow
	}
	dec.Reasons = append(dec.Reasons, "matched policy "+p.Name)
	return dec
}

// applyDefault sets the no-match verdict from the config.
func applyDefault(cfg Config, dec Decision) Decision {
	if cfg.DefaultDeny {
		dec.Verdict = VerdictDeny
		dec.Reasons = append(dec.Reasons, reasonDefaultDeny)
		return dec
	}
	dec.Verdict = VerdictAllow
	dec.Reasons = append(dec.Reasons, reasonDefaultAllow)
	return dec
}

// denyOnError is the fail-closed path for an un-evaluable policy.
func denyOnError(dec Decision, name string, err error) Decision {
	dec.Verdict = VerdictDeny
	dec.MatchedPolicy = name
	dec.Reasons = append(dec.Reasons, "policy "+name+" evaluation error: "+err.Error())
	return dec
}

// matchPolicy reports whether every SET condition is satisfied. An unparseable
// comparison / time literal returns a non-nil error (fail-closed at the call
// site).
func matchPolicy(c Conditions, ac AccessContext, risk float64) (bool, error) {
	if len(c.UserMemberOf) > 0 && !anyInGroups(ac.Groups, c.UserMemberOf) {
		return false, nil
	}
	if c.DeviceManaged != nil && *c.DeviceManaged != (ac.DevicePosture == PostureManaged) {
		return false, nil
	}
	if c.RiskScore != "" {
		ok, err := matchRisk(c.RiskScore, risk)
		if err != nil || !ok {
			return false, err
		}
	}
	if !matchGeo(c, ac.Country) {
		return false, nil
	}
	return matchTime(c, ac.Now)
}

func anyInGroups(have, want []string) bool {
	for _, w := range want {
		if contains(have, w) {
			return true
		}
	}
	return false
}

func matchRisk(expr string, risk float64) (bool, error) {
	op, threshold, err := parseComparison(expr)
	if err != nil {
		return false, err
	}
	return applyComparison(op, risk, threshold), nil
}

// matchGeo is fail-open: with no geo condition it matches; with a geo condition
// an unknown country never matches (an unknown geo neither satisfies an
// allowlist nor trips a denylist).
func matchGeo(c Conditions, country string) bool {
	if len(c.GeoIn) == 0 && len(c.GeoNotIn) == 0 {
		return true
	}
	if country == "" {
		return false
	}
	if len(c.GeoIn) > 0 && !containsFold(c.GeoIn, country) {
		return false
	}
	if len(c.GeoNotIn) > 0 && containsFold(c.GeoNotIn, country) {
		return false
	}
	return true
}

// matchTime evaluates the UTC time-of-day window. A zero clock makes a
// time-gated policy NOT match (the window is un-evaluable without a clock).
func matchTime(c Conditions, now time.Time) (bool, error) {
	if c.TimeAfter == "" && c.TimeBefore == "" {
		return true, nil
	}
	if now.IsZero() {
		return false, nil
	}
	after, before := 0, 24*60
	if c.TimeAfter != "" {
		m, err := parseHHMM(c.TimeAfter)
		if err != nil {
			return false, err
		}
		after = m
	}
	if c.TimeBefore != "" {
		m, err := parseHHMM(c.TimeBefore)
		if err != nil {
			return false, err
		}
		before = m
	}
	u := now.UTC()
	return inWindow(u.Hour()*60+u.Minute(), after, before), nil
}

// inWindow tests [after, before) minute-of-day, wrapping midnight when
// after > before.
func inWindow(cur, after, before int) bool {
	if after <= before {
		return cur >= after && cur < before
	}
	return cur >= after || cur < before
}

// parseComparison splits a "<op> <number>" comparison, e.g. ">= 0.5". The
// two-character operators are tested first so ">=" isn't mis-read as ">".
func parseComparison(expr string) (op string, threshold float64, err error) {
	s := strings.TrimSpace(expr)
	for _, cand := range []string{">=", "<=", "==", "!=", ">", "<"} {
		if !strings.HasPrefix(s, cand) {
			continue
		}
		n, perr := strconv.ParseFloat(strings.TrimSpace(s[len(cand):]), 64)
		if perr != nil {
			return "", 0, fmt.Errorf("conditionalaccess: comparison %q has an invalid number: %w", expr, perr)
		}
		return cand, n, nil
	}
	return "", 0, fmt.Errorf("conditionalaccess: comparison %q is missing a leading operator (>, >=, <, <=, ==, !=)", expr)
}

func applyComparison(op string, value, threshold float64) bool {
	switch op {
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case "==":
		return value == threshold
	case "!=":
		return value != threshold
	}
	return false
}

// parseHHMM parses a 24-hour "HH:MM" UTC time-of-day into minutes since
// midnight.
func parseHHMM(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, fmt.Errorf("conditionalaccess: invalid time-of-day %q (want HH:MM): %w", s, err)
	}
	return t.Hour()*60 + t.Minute(), nil
}
