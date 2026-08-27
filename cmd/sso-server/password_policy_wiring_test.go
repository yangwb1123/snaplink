package main

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

func TestWirePasswordPolicy_UnconfiguredIsNoOp(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}}
	b.wirePasswordPolicy()
	if len(b.opts) != 0 {
		t.Fatalf("unconfigured policy appended %d options", len(b.opts))
	}
	b.cfg.Authenticators.Password = &config.PasswordConfig{Policy: &config.PasswordPolicyConfig{}}
	b.wirePasswordPolicy()
	if len(b.opts) != 0 {
		t.Fatalf("zero-value policy appended %d options", len(b.opts))
	}
	if sso.NewServer().PasswordPolicyValidator() != nil {
		t.Fatal("default server unexpectedly has a password policy")
	}
}

func TestWirePasswordPolicy_MapsConfiguredPolicy(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{Authenticators: config.AuthenticatorsConfig{
		Password: &config.PasswordConfig{Policy: &config.PasswordPolicyConfig{
			MinLength: 12, RequireUpper: true, RequireDigit: true, MaxAgeDays: 30,
		}},
	}}}
	b.wirePasswordPolicy()
	if len(b.opts) != 1 {
		t.Fatalf("configured policy appended %d options, want 1", len(b.opts))
	}
	validator := sso.NewServer(b.opts...).PasswordPolicyValidator()
	if validator == nil {
		t.Fatal("configured policy was not wired")
	}
	if err := validator.ValidatePassword(context.Background(), "short1"); err == nil {
		t.Fatal("configured minimum policy accepted a short password")
	}
	if err := validator.ValidatePassword(context.Background(), "long-enough1"); err == nil {
		t.Fatal("configured uppercase policy accepted a lowercase password")
	}
	if err := validator.ValidatePassword(context.Background(), "Long-enough1"); err != nil {
		t.Fatalf("valid configured password rejected: %v", err)
	}
	age, ok := validator.(interface{ PasswordMaxAgeDays() int })
	if !ok || age.PasswordMaxAgeDays() != 30 {
		t.Fatalf("max age provider = (%v, %v), want (30, true)", age, ok)
	}
}
