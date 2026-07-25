package device

import (
	"testing"
	"time"
)

func TestTrustLabelForScore(t *testing.T) {
	tests := []struct {
		score float64
		want  string
	}{
		{0.9, "Very High"},
		{0.7, "High"},
		{0.5, "Medium"},
		{0.3, "Low"},
		{0.1, "Very Low"},
	}
	for _, tc := range tests {
		got := TrustLabelForScore(tc.score)
		if got != tc.want {
			t.Errorf("TrustLabelForScore(%v) = %q, want %q", tc.score, got, tc.want)
		}
	}
}

func TestDecayTrustScore_NoDecay(t *testing.T) {
	got := DecayTrustScore(0.9, 0)
	if got != 0.9 {
		t.Errorf("DecayTrustScore(0.9, 0) = %v, want 0.9", got)
	}
}

func TestDecayTrustScore_30Days(t *testing.T) {
	got := DecayTrustScore(0.9, 30)
	if got != 0.8 {
		t.Errorf("DecayTrustScore(0.9, 30) = %v, want 0.8", got)
	}
}

func TestDecayTrustScore_90Days(t *testing.T) {
	got := DecayTrustScore(0.9, 90)
	if got != 0.6 {
		t.Errorf("DecayTrustScore(0.9, 90) = %v, want 0.6", got)
	}
}

func TestDecayTrustScore_Minimum(t *testing.T) {
	got := DecayTrustScore(0.9, 365)
	if got < 0.2 {
		t.Errorf("DecayTrustScore(0.9, 365) = %v, want >= 0.2", got)
	}
}

func TestDecayTrustScore_NegativeDays(t *testing.T) {
	got := DecayTrustScore(0.9, -1)
	if got != 0.9 {
		t.Errorf("DecayTrustScore(0.9, -1) = %v, want 0.9", got)
	}
}

func TestDecayTrustScore_LowScoreDoesntGoBelowMin(t *testing.T) {
	got := DecayTrustScore(0.3, 60)
	if got != 0.2 {
		t.Errorf("DecayTrustScore(0.3, 60) = %v, want 0.2", got)
	}
}

func TestDecayTrustScore_LabelAfterDecay(t *testing.T) {
	score := DecayTrustScore(0.9, 60)
	// 0.9 - (60/30)*0.1 = 0.7 => "High"
	if label := TrustLabelForScore(score); label != "High" {
		t.Errorf("score=%v label=%q, expected High", score, label)
	}
}

func TestDecayOnDevice(t *testing.T) {
	device := &Device{
		TrustScore: 0.9,
		LastSeenAt: time.Now().Add(-45 * 24 * time.Hour),
	}
	days := int(time.Since(device.LastSeenAt).Hours() / 24)
	device.TrustScore = DecayTrustScore(device.TrustScore, days)
	device.TrustLabel = TrustLabelForScore(device.TrustScore)
	if device.TrustScore >= 0.9 {
		t.Errorf("after 45 days, trust should decay, got %v", device.TrustScore)
	}
	if device.TrustLabel == "Very High" {
		t.Errorf("after 45 days, label should not be Very High")
	}
}
