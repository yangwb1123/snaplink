package admin

import (
	"testing"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
)

func TestTrustLevelRange(t *testing.T) {
	tests := []struct {
		level   string
		wantMin float64
		wantMax float64
		wantOK  bool
	}{
		{"very_low", 0, 0.19, true},
		{"low", 0.2, 0.39, true},
		{"medium", 0.4, 0.59, true},
		{"high", 0.6, 0.79, true},
		{"very_high", 0.8, 1.0, true},
		{"unknown", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range tests {
		min, max, ok := trustLevelRange(tc.level)
		if ok != tc.wantOK || min != tc.wantMin || max != tc.wantMax {
			t.Errorf("trustLevelRange(%q) = (%v,%v,%v), want (%v,%v,%v)", tc.level, min, max, ok, tc.wantMin, tc.wantMax, tc.wantOK)
		}
	}
}

func TestFilterByField(t *testing.T) {
	devices := []*device.Device{
		{Platform: "iOS", Fingerprint: "fp1"},
		{Platform: "Android", Fingerprint: "fp2"},
		{Platform: "iOS", Fingerprint: "fp3"},
	}
	result := filterField(devices, func(d *device.Device) string { return d.Platform }, "iOS")
	if len(result) != 2 {
		t.Errorf("expected 2, got %d", len(result))
	}
}
