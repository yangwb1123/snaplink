package main

import (
	"testing"

	"github.com/yangwb1123/snaplink/config"
)

// wireTrustScoring (build_app_selfservice.go) is the reference sso-server's
// composition-root translation of config.TrustConfig.Serialization into
// sso.WithTrustScoreSerialization. These tests exercise it directly (same
// pattern as TestWireDR_* in build_app_dr_test.go) rather than through a full
// server, proving the byte-identical-when-off contract and that the Option
// is appended (in addition to WithTrustScorer) once either sub-flag is set.

// TestWireTrustScoring_SerializationDefaultOff_NoExtraOption proves that with
// trust.serialization's two flags left at their default (false), only
// WithTrustScorer is appended — the config's own documented contract that an
// absent/false serialization section changes nothing on the wire.
func TestWireTrustScoring_SerializationDefaultOff_NoExtraOption(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Trust.Enabled = true
	cfg.Trust.Weights = map[string]float64{"device_posture": 1}
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 1 {
		t.Fatalf("opts = %d, want 1 (WithTrustScorer only; serialization both-false must add nothing)", len(b.opts))
	}
}

// TestWireTrustScoring_StampSessionMetadataAddsOption proves setting just
// stamp_session_metadata appends WithTrustScoreSerialization alongside
// WithTrustScorer.
func TestWireTrustScoring_StampSessionMetadataAddsOption(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Trust.Enabled = true
	cfg.Trust.Weights = map[string]float64{"device_posture": 1}
	cfg.Trust.Serialization.StampSessionMetadata = true
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 2 {
		t.Fatalf("opts = %d, want 2 (WithTrustScorer + WithTrustScoreSerialization)", len(b.opts))
	}
}

// TestWireTrustScoring_IncludeTokenClaimAddsOption mirrors the above for the
// other sub-flag, proving either one independently triggers the wiring.
func TestWireTrustScoring_IncludeTokenClaimAddsOption(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Trust.Enabled = true
	cfg.Trust.Weights = map[string]float64{"device_posture": 1}
	cfg.Trust.Serialization.IncludeTokenClaim = true
	cfg.Trust.Serialization.ClaimName = "zt_trust"
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 2 {
		t.Fatalf("opts = %d, want 2 (WithTrustScorer + WithTrustScoreSerialization)", len(b.opts))
	}
}

// TestWireTrustScoring_TrustDisabled_SerializationNeverWiredEither proves
// that with trust.enabled=false (BuildTrustScorer returns (nil, nil)),
// wireTrustScoring returns before ever considering serialization — a
// dangling trust.serialization block with no trust.weights configured wires
// nothing at all, matching trust.enabled's own byte-identical-when-off
// contract.
func TestWireTrustScoring_TrustDisabled_SerializationNeverWiredEither(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Trust.Serialization.StampSessionMetadata = true
	cfg.Trust.Serialization.IncludeTokenClaim = true
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if err := b.wireTrustScoring(); err != nil {
		t.Fatalf("wireTrustScoring: %v", err)
	}
	if len(b.opts) != 0 {
		t.Fatalf("opts = %d, want 0 (trust.enabled=false must wire nothing)", len(b.opts))
	}
}
