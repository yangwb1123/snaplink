package trust_test

import (
	"math"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/trust"
)

var decayBase = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func sessAt(score float64, setAt time.Time) core.Session {
	return core.Session{ID: "s1", UserID: "u1", TrustScore: score, TrustSetAt: setAt}
}

func TestDecayedScore_Curve(t *testing.T) {
	t.Parallel()
	cfg := trust.DecayConfig{Interval: 5 * time.Minute, Factor: 0.95}
	cases := []struct {
		name    string
		elapsed time.Duration
		want    float64
	}{
		{"t0 no decay", 0, 1.0},
		{"one interval", 5 * time.Minute, 0.95},
		{"two intervals", 10 * time.Minute, 0.9025},
		{"ten intervals", 50 * time.Minute, math.Pow(0.95, 10)},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := trust.DecayedScore(sessAt(1.0, decayBase), decayBase.Add(c.elapsed), cfg)
			if math.Abs(got-c.want) > 1e-9 {
				t.Fatalf("DecayedScore(elapsed=%s) = %v, want %v", c.elapsed, got, c.want)
			}
		})
	}
}

func TestDecayedScore_MinScoreFloor(t *testing.T) {
	t.Parallel()
	cfg := trust.DecayConfig{Interval: time.Minute, Factor: 0.5, MinScore: 0.3}
	// After many halvings the raw curve is ~0, but MinScore clamps it.
	got := trust.DecayedScore(sessAt(1.0, decayBase), decayBase.Add(time.Hour), cfg)
	if got != 0.3 {
		t.Fatalf("decayed with MinScore floor = %v, want 0.3", got)
	}
}

func TestDecayedScore_FailOpenNoSignalOrDisabled(t *testing.T) {
	t.Parallel()
	live := trust.DecayConfig{Interval: 5 * time.Minute, Factor: 0.95}
	cases := []struct {
		name string
		sess core.Session
		cfg  trust.DecayConfig
		now  time.Time
		want float64
	}{
		// Feature off (zero cfg): the raw bound score passes through unchanged,
		// so a build without WithSessionTrustDecay never decays.
		{"disabled cfg passes raw score", sessAt(0.8, decayBase), trust.DecayConfig{}, decayBase.Add(time.Hour), 0.8},
		// No baseline bound (legacy/zero-value session): fail-open, no decay.
		{"zero TrustSetAt (legacy row)", sessAt(0.8, time.Time{}), live, decayBase.Add(time.Hour), 0.8},
		// Clock slew: now before baseline never inflates or errors.
		{"now before baseline", sessAt(0.8, decayBase), live, decayBase.Add(-time.Hour), 0.8},
		// Legacy row is exactly the zero value everywhere.
		{"fully-zero session", core.Session{}, live, decayBase, 0.0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			if got := trust.DecayedScore(c.sess, c.now, c.cfg); got != c.want {
				t.Fatalf("DecayedScore = %v, want %v", got, c.want)
			}
		})
	}
}

func TestDecayConfig_Enabled(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  trust.DecayConfig
		want bool
	}{
		{"zero value off", trust.DecayConfig{}, false},
		{"factor 1 is no-decay off", trust.DecayConfig{Interval: time.Minute, Factor: 1}, false},
		{"factor >1 off", trust.DecayConfig{Interval: time.Minute, Factor: 1.5}, false},
		{"interval 0 off", trust.DecayConfig{Factor: 0.9}, false},
		{"valid on", trust.DecayConfig{Interval: time.Minute, Factor: 0.9}, true},
	}
	for _, c := range cases {
		if got := c.cfg.Enabled(); got != c.want {
			t.Errorf("%s: Enabled() = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestBelowFloor(t *testing.T) {
	t.Parallel()
	cfg := trust.DecayConfig{Interval: 5 * time.Minute, Factor: 0.95, Floor: 0.6}
	// 1.0 decayed over 60min: 0.95^12 ≈ 0.540 < 0.6 → below floor.
	if !trust.BelowFloor(sessAt(1.0, decayBase), decayBase.Add(time.Hour), cfg) {
		t.Fatalf("expected below floor after 60min decay")
	}
	// Fresh session: score 1.0 >= 0.6 → not below.
	if trust.BelowFloor(sessAt(1.0, decayBase), decayBase, cfg) {
		t.Fatalf("fresh session must not be below floor")
	}
	// Fail-open: no baseline bound → never below floor.
	if trust.BelowFloor(sessAt(0.1, time.Time{}), decayBase.Add(time.Hour), cfg) {
		t.Fatalf("no-signal session must fail-open (not below floor)")
	}
	// Disabled cfg → never below floor.
	if trust.BelowFloor(sessAt(0.1, decayBase), decayBase.Add(time.Hour), trust.DecayConfig{Floor: 0.6}) {
		t.Fatalf("disabled cfg must fail-open (not below floor)")
	}
}

func TestStepUpRequiredForTrust(t *testing.T) {
	t.Parallel()
	cfg := trust.DecayConfig{Interval: 5 * time.Minute, Factor: 0.95}
	decayed := sessAt(1.0, decayBase) // decays below 0.6 after 60min

	// Gate disabled for the operation (minTrust<=0) never challenges.
	if trust.StepUpRequiredForTrust(decayed, decayBase.Add(time.Hour), cfg, 0) {
		t.Fatalf("minTrust<=0 must not challenge")
	}
	// Live decayed score below the per-op threshold → challenge.
	if !trust.StepUpRequiredForTrust(decayed, decayBase.Add(time.Hour), cfg, 0.6) {
		t.Fatalf("below-threshold decayed score must challenge")
	}
	// Fresh session clears the bar → no challenge.
	if trust.StepUpRequiredForTrust(decayed, decayBase, cfg, 0.6) {
		t.Fatalf("fresh session above threshold must not challenge")
	}
	// Agent flag forces a challenge even for a high-trust-looking session.
	flagged := sessAt(1.0, decayBase)
	flagged.StepUpRequired = true
	if !trust.StepUpRequiredForTrust(flagged, decayBase, cfg, 0.6) {
		t.Fatalf("agent-flagged session must challenge")
	}
	// Fail-open: no bound signal never challenges (spec Edge Cases).
	if trust.StepUpRequiredForTrust(sessAt(0.0, time.Time{}), decayBase.Add(time.Hour), cfg, 0.6) {
		t.Fatalf("no-signal session must fail-open (no challenge)")
	}
	// Fail-open: disabled cfg never challenges (unless already flagged).
	if trust.StepUpRequiredForTrust(sessAt(0.1, decayBase), decayBase, trust.DecayConfig{}, 0.6) {
		t.Fatalf("disabled cfg must fail-open (no challenge)")
	}
}
