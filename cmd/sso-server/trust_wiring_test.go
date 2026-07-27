package main

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

// trust_wiring_test.go proves ROADMAP 6g: the previously dead trust config
// section now wires sso.WithTrustScorer iff trust.enabled, reusing the
// anomaly stores through the composition-root adapters, and an absent/
// disabled section appends no Option (byte-identical build).

func trustEnabledConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Trust.Enabled = true
	cfg.Trust.Weights = map[string]float64{"geo_risk": 2, "device_posture": 1}
	cfg.Trust.DevicePosture.DefaultScore = 0.3
	return cfg
}

func TestTrustScoring_NotWiredWhenDisabled(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 0 {
		t.Fatalf("disabled trust appended %d opts; want 0 (byte-identical build)", len(b.opts))
	}
}

func TestTrustScoring_WiredWhenEnabled(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: trustEnabledConfig(), logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("enabled trust appended %d opts; want exactly 1 (WithTrustScorer)", len(b.opts))
	}
}

func TestTrustScoring_AnomalyBackedLookupsWire(t *testing.T) {
	t.Parallel()
	cfg := trustEnabledConfig()
	cfg.Trust.Weights = map[string]float64{"ip_reputation": 1, "behavior": 1}
	// Hex salt, as the anomaly config recommends — proves the shared
	// decodeAnomalySalt path feeds the adapter.
	cfg.Anomaly.IPSalt = "00112233445566778899aabbccddeeff"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	b.anomalyRT = &anomalyRuntime{
		ipFailCounter: defaultimpl.NewMemoryIPFailureCounter(),
		recentStore:   defaultimpl.NewMemoryRecentLoginStore(),
	}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("anomaly-backed trust appended %d opts; want exactly 1", len(b.opts))
	}
}

func TestTrustScoring_FailsLoudOnDeadConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		weights map[string]float64
	}{
		{"enabled without weights", nil},
		{"typo'd scorer name", map[string]float64{"geo": 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cfg := &config.Config{}
			cfg.Trust.Enabled = true
			cfg.Trust.Weights = tc.weights
			b := &appBuilder{cfg: cfg, logger: quietLogger()}
			if err := b.wireTrustScoring(); err == nil {
				t.Error("wireTrustScoring accepted a config that would silently score nothing; want loud boot failure")
			}
		})
	}
}

// TestTrustScoring_BuildAppBoots proves the full buildApp path with trust
// enabled — including the sso_trust_score collector registration on the
// per-build metrics registry (promauto panics on a duplicate, so a boot
// without error is the assertion) — boots cleanly.
func TestTrustScoring_BuildAppBoots(t *testing.T) {
	t.Parallel()
	cfg := trustEnabledConfig()
	cfg.Metrics.Enabled = true
	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp with trust.enabled: %v", err)
	}
	shutdownApp(t, a)
}
