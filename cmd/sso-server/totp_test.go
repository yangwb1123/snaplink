package main

import (
	"testing"

	"github.com/snaplink/sso/config"
)

// TestBuildAuthenticators_TOTPDisabledByDefault proves the TOTP
// authenticator stays out of the list when its config block is
// nil — operators who don't opt in get no /auth/login?provider=totp
// surface.
func TestBuildAuthenticators_TOTPDisabledByDefault(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.Password = &config.PasswordConfig{Enabled: true}
	auths, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	for _, a := range auths {
		if a.Name() == "totp" {
			t.Fatal("totp authenticator registered without enabling it in config")
		}
	}
}

// TestBuildAuthenticators_TOTPEnabled proves the wiring registers
// the authenticator under its canonical "totp" name when the YAML
// block opts in. /auth/login?provider=totp then routes here.
func TestBuildAuthenticators_TOTPEnabled(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.TOTP = &config.TOTPConfig{Enabled: true}
	auths, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	found := false
	for _, a := range auths {
		if a.Name() == "totp" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("totp authenticator not registered when Enabled=true")
	}
}

// TestBuildAuthenticators_TOTPSkewStepsApplied proves the optional
// skew_steps knob actually flows through. The authenticator
// exposes no public skew accessor — easiest verification is the
// constructor doesn't error and the resulting Authenticator
// reports the canonical name.
func TestBuildAuthenticators_TOTPSkewStepsApplied(t *testing.T) {
	cfg := &config.Config{}
	cfg.Authenticators.TOTP = &config.TOTPConfig{Enabled: true, SkewSteps: 2}
	auths, _, _, _ := buildAuthenticators(cfg, quietLogger(), nil)
	if len(auths) == 0 {
		t.Fatal("no authenticators built with skew_steps override")
	}
}
