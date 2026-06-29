package main

import (
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildplatform"
	"github.com/snaplink/sso/config"
)

func TestSigningKeyRotationConfig(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		in      config.KeyRotationConfig
		wantOK  bool
		wantInt time.Duration
	}{
		{"disabled", config.KeyRotationConfig{Enabled: false, Interval: time.Hour}, false, 0},
		{"enabled but zero interval", config.KeyRotationConfig{Enabled: true, Interval: 0}, false, 0},
		{"enabled but negative interval", config.KeyRotationConfig{Enabled: true, Interval: -time.Hour}, false, 0},
		{"enabled valid", config.KeyRotationConfig{Enabled: true, Interval: 90 * 24 * time.Hour, GracePeriod: 7 * 24 * time.Hour}, true, 90 * 24 * time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rc, ok := serverbuildplatform.SigningKeyRotationConfig(tc.in)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && rc.Interval != tc.wantInt {
				t.Errorf("interval = %v, want %v", rc.Interval, tc.wantInt)
			}
			if ok && rc.GracePeriod != tc.in.GracePeriod {
				t.Errorf("grace = %v, want %v", rc.GracePeriod, tc.in.GracePeriod)
			}
		})
	}
}
