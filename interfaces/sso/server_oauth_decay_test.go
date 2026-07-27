package sso

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

// ---- DecayTrustScore integration with computeDeviceTrustScore ----

func TestDecayThenCompute_NewDevice(t *testing.T) {
	// New device: no existing record → no decay, compute from scratch
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true}
	score := computeDeviceTrustScore(secCtx, 1, nil)
	if score != 0.30 {
		t.Errorf("new device: got %v, want 0.30", score)
	}
}

func TestDecayThenCompute_FreshDevice(t *testing.T) {
	// Device seen 1 hour ago → almost no decay
	existing := &device.Device{
		TrustScore: 0.8,
		LastSeenAt: time.Now().Add(-1 * time.Hour),
	}
	daysSinceLastSeen := int(time.Since(existing.LastSeenAt).Hours() / 24)
	existing.TrustScore = device.DecayTrustScore(existing.TrustScore, daysSinceLastSeen)
	score := computeDeviceTrustScore(nil, 5, existing)
	if score < 0.79 || score > 0.9 {
		t.Errorf("fresh device: got %v, want ~0.8-0.9", score)
	}
}

func TestDecayThenCompute_OldDevice(t *testing.T) {
	// Device seen 90 days ago → significant decay
	existing := &device.Device{
		TrustScore: 0.9,
		LastSeenAt: time.Now().Add(-90 * 24 * time.Hour),
	}
	daysSinceLastSeen := int(time.Since(existing.LastSeenAt).Hours() / 24)
	existing.TrustScore = device.DecayTrustScore(existing.TrustScore, daysSinceLastSeen)
	score := computeDeviceTrustScore(nil, 5, existing)
	if score > 0.85 {
		t.Errorf("old device (90d) should have reduced trust: got %v", score)
	}
}

func TestDecayThenCompute_StableDeviceStillHigh(t *testing.T) {
	// Device with 20 logins, seen 30 days ago → should stay at 0.85 (stabilized)
	existing := &device.Device{
		TrustScore: 0.9,
		LoginCount: 20,
		LastSeenAt: time.Now().Add(-30 * 24 * time.Hour),
	}
	daysSinceLastSeen := int(time.Since(existing.LastSeenAt).Hours() / 24)
	existing.TrustScore = device.DecayTrustScore(existing.TrustScore, daysSinceLastSeen)
	score := computeDeviceTrustScore(nil, 20, existing)
	if score != 0.85 {
		t.Errorf("stabilized device should be 0.85 despite decay, got %v", score)
	}
}

// ---- DecayTrustScore edge cases ----

func TestDecayTrustScore_ZeroLastSeen(t *testing.T) {
	// Device with zero LastSeenAt (newly created with no activity)
	score := device.DecayTrustScore(0.9, 0)
	if score != 0.9 {
		t.Errorf("zero days should not decay: got %v, want 0.9", score)
	}
}

func TestDecayTrustScore_ClockSkew(t *testing.T) {
	// Negative days (future LastSeenAt due to clock skew)
	score := device.DecayTrustScore(0.9, -5)
	if score != 0.9 {
		t.Errorf("negative days should not decay: got %v, want 0.9", score)
	}
}

func TestDecayTrustScore_AlreadyLow(t *testing.T) {
	// Already low trust shouldn't go below minimum
	score := device.DecayTrustScore(0.15, 60)
	if score < 0.2 {
		t.Errorf("low trust should floor at 0.2: got %v", score)
	}
}

func TestDecayTrustScore_MaxDecay(t *testing.T) {
	// Max decay is 0.5, so 0.9 - 0.5 = 0.4
	score := device.DecayTrustScore(0.9, 365)
	if score != 0.4 {
		t.Errorf("max decay should be 0.4 from 0.9: got %v", score)
	}
}

func TestDecayTrustScore_MaxDecayLowInitial(t *testing.T) {
	// 0.5 - 0.5 = 0.0, but floors at 0.2
	score := device.DecayTrustScore(0.5, 365)
	if score < 0.2 {
		t.Errorf("should floor at 0.2: got %v", score)
	}
}

func TestDecayTrustScore_LabelConsistency(t *testing.T) {
	decayed := device.DecayTrustScore(0.9, 90)
	label := device.TrustLabelForScore(decayed)
	// 0.9 - 0.3 = 0.6 → "Medium" (0.4-0.59) or "High" (0.6-0.79)
	if label != "Medium" && label != "High" {
		t.Errorf("after 90d decay score=%.2f, label=%q, expected Medium or High", decayed, label)
	}
}

// ---- Full integration via registerLoginDevice simulation ----

func TestDecayIntegration_FullFlow(t *testing.T) {
	// Simulate registerLoginDevice's decay + compute flow
	existing := &device.Device{TrustScore: 0.9, LastSeenAt: time.Now().Add(-60 * 24 * time.Hour)}
	secCtx := &device.LoginSecurityContext{}

	// Step 1: Decay
	days := int(time.Since(existing.LastSeenAt).Hours() / 24)
	existing.TrustScore = device.DecayTrustScore(existing.TrustScore, days)

	// Step 2: Compute (loginCount=2, so bonus applies)
	score := computeDeviceTrustScore(secCtx, 2, existing)

	// 60d decay: 0.9 - 0.2 = 0.7. Then compute uses existing=0.7, adds (2-1)*0.02 = 0.72
	if score < 0.65 || score > 0.8 {
		t.Errorf("decay+compute integration: got %v, want ~0.72", score)
	}
}

func TestDecayIntegration_NewDeviceNoDecay(t *testing.T) {
	// New device (no existing) → no decay applied
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true}
	score := computeDeviceTrustScore(secCtx, 1, nil)
	if score != 0.30 {
		t.Errorf("new device no decay: got %v, want 0.30", score)
	}
}

func TestDecayIntegration_StabilizedAfterDecay(t *testing.T) {
	// Device with 15 logins, high trust, 60d idle → decay to 0.7, then stabilize at 0.85
	existing := &device.Device{TrustScore: 0.9, LoginCount: 15, LastSeenAt: time.Now().Add(-60 * 24 * time.Hour)}
	days := int(time.Since(existing.LastSeenAt).Hours() / 24)
	existing.TrustScore = device.DecayTrustScore(existing.TrustScore, days)
	score := computeDeviceTrustScore(nil, 15, existing)
	if score != 0.85 {
		t.Errorf("stabilized device after decay: got %v, want 0.85", score)
	}
}
