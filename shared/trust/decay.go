package trust

import (
	"math"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// Session trust decay (Zero Trust Framework Phase 3 — continuous verification &
// session trust decay; see the Direction 3 analysis doc). A session is minted
// with a bound trust score (core.Session.TrustScore) at a baseline instant
// (core.Session.TrustSetAt); this file provides the PURE, table-testable decay
// curve that erodes that score over time plus the min-trust gate decision a
// high-risk operation consults. Nothing here reaches a store, a clock, or the
// request path — the continuous-verification agent (platform/lifecycle/
// continuousverify) and the interfaces/sso gate method feed it a session + a
// caller-injected `now`, so both the math and its callers stay deterministic.
//
// FAIL-OPEN is the cardinal invariant (spec Edge Cases): a session carrying no
// bound trust signal (TrustSetAt zero) or a build with decay unconfigured
// behaves EXACTLY as today — DecayedScore returns the raw bound score and the
// gate never challenges. The decay/gate are advisory infra; they never
// hard-deny on absent scoring data.

// DecayConfig parameterizes the exponential trust-decay curve and the
// continuous-verification agent's step-up floor. The zero value disables decay
// entirely (Interval <= 0), so a Server wired without WithSessionTrustDecay is
// byte-identical to today.
type DecayConfig struct {
	// Interval is the decay period: the bound score is multiplied by Factor
	// once per Interval of elapsed wall-clock (continuous, not stepped — see
	// DecayedScore). <= 0 disables decay (the feature-off zero value).
	Interval time.Duration

	// Factor is the per-Interval multiplier, in the open range (0, 1). 0.95
	// erodes ~5% of the remaining score every Interval. A value <= 0 or >= 1
	// is treated as "no decay" (a Factor of exactly 1 never erodes; > 1 would
	// be growth, which is nonsense for decay and is clamped out).
	Factor float64

	// Floor is the continuous-verification agent's step-up threshold: a live
	// session whose DecayedScore falls BELOW Floor is marked for step-up /
	// refresh on its next request (core.Session.StepUpRequired). Distinct from
	// the per-operation min-trust the gate enforces (that is passed to
	// StepUpRequiredForTrust) so an operator can run the background agent at a
	// lenient floor while a specific high-risk endpoint demands more.
	Floor float64

	// MinScore is the asymptotic lower bound: DecayedScore never returns less
	// than MinScore, so an old-but-legitimate session's score doesn't decay to
	// a hard 0 (which the gate would read as "maximally suspicious"). Zero
	// leaves the natural exp-decay-toward-0 curve.
	MinScore float64
}

// Enabled reports whether decay is configured. False (the zero value) makes
// every downstream helper a fail-open no-op.
func (c DecayConfig) Enabled() bool {
	return c.Interval > 0 && c.Factor > 0 && c.Factor < 1
}

// DecayedScore returns the session's trust score eroded from its bound value
// (sess.TrustScore, set at sess.TrustSetAt) to `now` under cfg's exponential
// curve: score * Factor^(elapsed/Interval), clamped to [MinScore, 1].
//
// It is fail-open on absence: when decay is unconfigured (cfg.Enabled() false),
// the session carries no baseline (TrustSetAt zero), or `now` precedes the
// baseline (clock slew), it returns the raw bound score UNCHANGED — a session
// with no trust signal (TrustScore 0, TrustSetAt zero) yields 0, which the gate
// reads as "no signal → allow", never "deny".
func DecayedScore(sess core.Session, now time.Time, cfg DecayConfig) float64 {
	base := ClampScore(sess.TrustScore)
	if !cfg.Enabled() || sess.TrustSetAt.IsZero() {
		return base
	}
	elapsed := now.Sub(sess.TrustSetAt)
	if elapsed <= 0 {
		return base
	}
	intervals := float64(elapsed) / float64(cfg.Interval)
	decayed := base * math.Pow(cfg.Factor, intervals)
	if decayed < cfg.MinScore {
		decayed = cfg.MinScore
	}
	return ClampScore(decayed)
}

// BelowFloor reports whether the session's live decayed score has dropped below
// cfg.Floor — the predicate the continuous-verification agent uses to decide a
// session needs marking. Fail-open: a session with no bound signal (TrustSetAt
// zero) or an unconfigured decay is never below floor.
func BelowFloor(sess core.Session, now time.Time, cfg DecayConfig) bool {
	if !cfg.Enabled() || sess.TrustSetAt.IsZero() {
		return false
	}
	return DecayedScore(sess, now, cfg) < cfg.Floor
}

// StepUpRequiredForTrust is the min-trust gate decision a high-risk operation
// (admin mutation, self-service credential change, ...) consults: it reports
// whether the caller's session must be challenged for step-up before the
// operation proceeds. minTrust is the per-operation threshold — the operation's
// own bar, independent of the agent's cfg.Floor.
//
// FAIL-OPEN (spec Edge Cases): returns false (allow) when the gate is disabled
// for this operation (minTrust <= 0), when decay is unconfigured, or when the
// session carries no bound trust signal (TrustSetAt zero). It returns true only
// on a POSITIVE signal to distrust: the continuous-verification agent already
// flagged the session (sess.StepUpRequired) OR the live decayed score is below
// minTrust. The flag is honored first so a marked session is challenged even by
// an operation whose own minTrust it would otherwise clear.
func StepUpRequiredForTrust(sess core.Session, now time.Time, cfg DecayConfig, minTrust float64) bool {
	if minTrust <= 0 {
		return false
	}
	if sess.StepUpRequired {
		return true
	}
	if !cfg.Enabled() || sess.TrustSetAt.IsZero() {
		return false
	}
	return DecayedScore(sess, now, cfg) < minTrust
}
