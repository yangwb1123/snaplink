package sso

import (
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

// ---- computeDeviceTrustScore adversarial tests ----

func TestAdversarial_ComputeTrust_NewDeviceDominatesLocation(t *testing.T) {
	// Both DeviceIsNew AND LocationIsNew true → DeviceIsNew should win (0.3)
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true, LocationIsNew: true}
	score := computeDeviceTrustScore(secCtx, 1, nil)
	// First login: no bonus. New device floor: 0.3
	if score != 0.30 {
		t.Errorf("both new device+location: got %v, want 0.30", score)
	}
}

func TestAdversarial_ComputeTrust_LocationNewForKnownDevice(t *testing.T) {
	// Known device (loginCount=5) from new location → score should be ~0.42
	secCtx := &device.LoginSecurityContext{LocationIsNew: true}
	score := computeDeviceTrustScore(secCtx, 5, nil)
	// 0.4 + (5-1)*0.02 = 0.48
	if score < 0.45 || score > 0.5 {
		t.Errorf("known device new location (count=5): got %v, want ~0.48", score)
	}
}

func TestAdversarial_ComputeTrust_ExistingTrustCarriedForward(t *testing.T) {
	existing := &device.Device{TrustScore: 0.8}
	score := computeDeviceTrustScore(nil, 5, existing)
	// Existing 0.8 + (5-1)*0.02 = 0.88
	if score < 0.85 || score > 0.9 {
		t.Errorf("existing trust 0.8 carried forward: got %v, want ~0.88", score)
	}
}

func TestAdversarial_ComputeTrust_StabilizedDevice(t *testing.T) {
	// Device with 10+ logins stabilizes at 0.85
	existing := &device.Device{TrustScore: 0.9}
	score := computeDeviceTrustScore(nil, 15, existing)
	if score != 0.85 {
		t.Errorf("stabilized device: got %v, want 0.85", score)
	}
}

func TestAdversarial_ComputeTrust_NewDeviceLoginCount1(t *testing.T) {
	// New device with exactly 1 login: no loginCount bonus, score = 0.3
	secCtx := &device.LoginSecurityContext{DeviceIsNew: true}
	score := computeDeviceTrustScore(secCtx, 1, nil)
	if score != 0.30 {
		t.Errorf("new device count=1: got %v, want 0.30", score)
	}
}

func TestAdversarial_ComputeTrust_NegativeExistingTrust(t *testing.T) {
	// Edge: existing trust is negative (corrupted data)
	existing := &device.Device{TrustScore: -0.5}
	score := computeDeviceTrustScore(nil, 5, existing)
	if score < 0.1 {
		t.Errorf("negative trust should floor at 0.1, got %v", score)
	}
}

func TestAdversarial_ComputeTrust_ZeroExistingTrust(t *testing.T) {
	// Zero trust floors at minimum 0.1
	existing := &device.Device{TrustScore: 0}
	score := computeDeviceTrustScore(nil, 1, existing)
	if score < 0.1 {
		t.Errorf("zero existing trust should floor at 0.1, got %v", score)
	}
}

func TestAdversarial_ComputeTrust_HighLoginCountOverflow(t *testing.T) {
	// Very high login count (overflow-like)
	existing := &device.Device{TrustScore: 0.5}
	score := computeDeviceTrustScore(nil, 999999, existing)
	if score > 0.95 {
		t.Errorf("should cap at 0.95, got %v", score)
	}
}

// ---- deviceAwareTTL adversarial tests ----

func TestAdversarial_DeviceAwareTTL_ZeroClientTTL(t *testing.T) {
	dc := &deviceContext{SecurityCtx: &device.LoginSecurityContext{DeviceIsNew: true}}
	result := deviceAwareTTL(0, dc, 0)
	if result != 0 {
		t.Errorf("zero client TTL should return 0, got %v", result)
	}
}

func TestAdversarial_DeviceAwareTTL_NegativeClientTTL(t *testing.T) {
	dc := &deviceContext{SecurityCtx: &device.LoginSecurityContext{DeviceIsNew: true}}
	result := deviceAwareTTL(-1*time.Second, dc, 0)
	if result != -1*time.Second {
		t.Errorf("negative client TTL should pass through, got %v", result)
	}
}

func TestAdversarial_DeviceAwareTTL_NilSecurityCtx(t *testing.T) {
	dc := &deviceContext{SecurityCtx: nil}
	result := deviceAwareTTL(3600*time.Second, dc, 0)
	if result != 3600*time.Second {
		t.Errorf("nil SecurityCtx should keep TTL, got %v", result)
	}
}

// ---- uaSummary adversarial tests ----

func TestAdversarial_UASummary_MalformedUA(t *testing.T) {
	tests := []string{
		"   ",                // whitespace only
		"Mozilla/5.0",        // incomplete UA
		string([]byte{0xff}), // binary garbage
	}
	for _, ua := range tests {
		result := uaSummary(ua)
		if result == "" {
			t.Errorf("uaSummary(%q) should not be empty", ua)
		}
	}
}

func TestAdversarial_UASummary_VeryLongUA(t *testing.T) {
	longUA := "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) " +
		"AppleWebKit/605.1.15 (KHTML, like Gecko) " +
		"Version/17.4 Mobile/15E148 Safari/604.1 " +
		"Chrome/125.0.0.0 " +
		"Edge/125.0.0.0 "
	result := uaSummary(longUA)
	if result == "" {
		t.Errorf("long UA should return a summary, got empty")
	}
}
