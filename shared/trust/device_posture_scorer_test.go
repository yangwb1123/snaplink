package trust_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/shared/trust"
)

func TestDevicePostureScorer_AlwaysReturnsConfiguredDefault(t *testing.T) {
	scorer := trust.NewDevicePostureScorer(0.3)

	for i := 0; i < 3; i++ {
		score, err := scorer.Score(context.Background(), trust.TrustSignals{DeviceHints: map[string]string{"whatever": "value"}})
		if err != nil {
			t.Fatalf("Score returned error: %v", err)
		}
		if score.Value != 0.3 {
			t.Fatalf("Value = %v, want 0.3", score.Value)
		}
		if len(score.Reasons) != 1 || score.Reasons[0] != "device_posture:not_integrated" {
			t.Fatalf("Reasons = %v, want [device_posture:not_integrated]", score.Reasons)
		}
	}
}

func TestDevicePostureScorer_ClampsOutOfRangeDefault(t *testing.T) {
	if got := trust.NewDevicePostureScorer(5.0).Default.Value; got != 1 {
		t.Fatalf("Default.Value = %v, want clamped to 1", got)
	}
	if got := trust.NewDevicePostureScorer(-5.0).Default.Value; got != 0 {
		t.Fatalf("Default.Value = %v, want clamped to 0", got)
	}
}

func TestDevicePostureScorer_Name(t *testing.T) {
	if got := (&trust.DevicePostureScorer{}).Name(); got != "device_posture" {
		t.Fatalf("Name() = %q, want device_posture", got)
	}
}
