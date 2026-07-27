package selfservice

import (
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

// ---- HandleMyDevices filter adversarial tests ----

func TestDeviceFilter_TrustLabelCaseSensitive(t *testing.T) {
	// Trust label filtering is case-sensitive. "very high" ≠ "Very High"
	// This test documents the current behavior (intentional: labels are
	// canonical identifiers, not user input).
	devices := []*device.Device{
		{TrustLabel: "Very High"},
		{TrustLabel: "Low"},
	}
	filtered := filterByTrustLabel(devices, "very high")
	if len(filtered) != 0 {
		t.Errorf("case-sensitive filter should match 0 for 'very high', got %d", len(filtered))
	}
	filtered = filterByTrustLabel(devices, "Very High")
	if len(filtered) != 1 {
		t.Errorf("case-sensitive filter should match 1 for 'Very High', got %d", len(filtered))
	}
}

func TestDeviceFilter_TrustLabelEmpty(t *testing.T) {
	devices := []*device.Device{
		{TrustLabel: "Very High"},
		{TrustLabel: "Low"},
	}
	filtered := filterByTrustLabel(devices, "")
	if len(filtered) != 2 {
		t.Errorf("empty filter should return all devices, got %d", len(filtered))
	}
}

func TestDeviceFilter_TrustLabelUnknown(t *testing.T) {
	devices := []*device.Device{
		{TrustLabel: "Very High"},
	}
	filtered := filterByTrustLabel(devices, "Unknown")
	if len(filtered) != 0 {
		t.Errorf("unknown label should return 0, got %d", len(filtered))
	}
}

func TestDeviceFilter_SuspiciousTrue(t *testing.T) {
	devices := []*device.Device{
		{Suspicious: true, Fingerprint: "fp1"},
		{Suspicious: false, Fingerprint: "fp2"},
		{Suspicious: true, Fingerprint: "fp3"},
	}
	filtered := filterBySuspicious(devices, "true")
	if len(filtered) != 2 {
		t.Errorf("suspicious=true should return 2, got %d", len(filtered))
	}
}

func TestDeviceFilter_SuspiciousNotTrue(t *testing.T) {
	devices := []*device.Device{
		{Suspicious: true, Fingerprint: "fp1"},
		{Suspicious: false, Fingerprint: "fp2"},
	}
	// Any value other than "true" should NOT filter
	filtered := filterBySuspicious(devices, "false")
	if len(filtered) != 2 {
		t.Errorf("suspicious=false should pass through all, got %d", len(filtered))
	}
	filtered = filterBySuspicious(devices, "True") // case-sensitive
	if len(filtered) != 2 {
		t.Errorf("suspicious=True should pass through all (case-sensitive), got %d", len(filtered))
	}
	filtered = filterBySuspicious(devices, "")
	if len(filtered) != 2 {
		t.Errorf("suspicious='' should pass through all, got %d", len(filtered))
	}
}

func TestDeviceFilter_Combined(t *testing.T) {
	devices := []*device.Device{
		{TrustLabel: "Low", Suspicious: true, Fingerprint: "fp1"},
		{TrustLabel: "Low", Suspicious: false, Fingerprint: "fp2"},
		{TrustLabel: "Very High", Suspicious: true, Fingerprint: "fp3"},
		{TrustLabel: "Very High", Suspicious: false, Fingerprint: "fp4"},
	}
	// First filter by trust_label=Low, then filter by suspicious=true
	filtered := filterByTrustLabel(devices, "Low")
	filtered = filterBySuspicious(filtered, "true")
	if len(filtered) != 1 {
		t.Errorf("Low + suspicious should return 1, got %d", len(filtered))
	}
	if filtered[0].Fingerprint != "fp1" {
		t.Errorf("expected fp1, got %s", filtered[0].Fingerprint)
	}
}

// filter helpers extracted from HandleMyDevices for unit testing
func filterByTrustLabel(devices []*device.Device, label string) []*device.Device {
	if label == "" { return devices }
	var out []*device.Device
	for _, d := range devices {
		if d.TrustLabel == label { out = append(out, d) }
	}
	return out
}

func filterBySuspicious(devices []*device.Device, val string) []*device.Device {
	if val != "true" { return devices }
	var out []*device.Device
	for _, d := range devices {
		if d.Suspicious { out = append(out, d) }
	}
	return out
}
