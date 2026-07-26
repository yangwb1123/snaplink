package oauthspi

import (
	"testing"
	"time"
)

func TestAuthCodeIsExpired(t *testing.T) {
	now := time.Now()

	t.Run("expired code", func(t *testing.T) {
		c := &AuthCode{ExpiresAt: now.Add(-1 * time.Hour)}
		if !c.IsExpired() {
			t.Error("expected expired for past timestamp")
		}
	})

	t.Run("valid code", func(t *testing.T) {
		c := &AuthCode{ExpiresAt: now.Add(1 * time.Hour)}
		if c.IsExpired() {
			t.Error("expected not expired for future timestamp")
		}
	})

	t.Run("zero expiration", func(t *testing.T) {
		c := &AuthCode{}
		if !c.IsExpired() {
			t.Error("expected expired for zero timestamp")
		}
	})
}

func TestDeviceCodeIsExpired(t *testing.T) {
	now := time.Now()

	t.Run("expired device code", func(t *testing.T) {
		d := &DeviceCode{ExpiresAt: now.Add(-1 * time.Hour)}
		if !d.IsExpired() {
			t.Error("expected expired for past timestamp")
		}
	})

	t.Run("valid device code", func(t *testing.T) {
		d := &DeviceCode{ExpiresAt: now.Add(1 * time.Hour)}
		if d.IsExpired() {
			t.Error("expected not expired for future timestamp")
		}
	})
}

func TestRefreshTokenIsExpired(t *testing.T) {
	now := time.Now()

	t.Run("expired refresh token", func(t *testing.T) {
		r := &RefreshToken{ExpiresAt: now.Add(-1 * time.Hour)}
		if !r.IsExpired() {
			t.Error("expected expired for past timestamp")
		}
	})

	t.Run("valid refresh token", func(t *testing.T) {
		r := &RefreshToken{ExpiresAt: now.Add(24 * time.Hour)}
		if r.IsExpired() {
			t.Error("expected not expired for future timestamp")
		}
	})

	t.Run("zero expiration", func(t *testing.T) {
		r := &RefreshToken{}
		if !r.IsExpired() {
			t.Error("expected expired for zero timestamp")
		}
	})
}

func TestRefreshTokenFields(t *testing.T) {
	now := time.Now()
	rt := &RefreshToken{
		UserID:    "user-1",
		ClientID:  "client-1",
		FamilyID:  "family-1",
		ExpiresAt: now.Add(24 * time.Hour),
		IssuedAt:  now,
		Scopes:    []string{"openid", "profile"},
	}

	if rt.UserID != "user-1" {
		t.Errorf("expected UserID 'user-1', got %q", rt.UserID)
	}
	if rt.FamilyID != "family-1" {
		t.Errorf("expected FamilyID 'family-1', got %q", rt.FamilyID)
	}
	if rt.ClientID != "client-1" {
		t.Errorf("expected ClientID 'client-1', got %q", rt.ClientID)
	}
	if len(rt.Scopes) != 2 {
		t.Errorf("expected 2 scopes, got %d", len(rt.Scopes))
	}
}

func TestRefreshTokenThumbprint(t *testing.T) {
	t.Run("produces consistent thumbprint", func(t *testing.T) {
		tp1 := RefreshTokenThumbprint("token-abc")
		tp2 := RefreshTokenThumbprint("token-abc")
		if tp1 != tp2 {
			t.Errorf("expected consistent thumbprint, got %q vs %q", tp1, tp2)
		}
	})

	t.Run("different tokens produce different thumbprints", func(t *testing.T) {
		tp1 := RefreshTokenThumbprint("token-abc")
		tp2 := RefreshTokenThumbprint("token-xyz")
		if tp1 == tp2 {
			t.Error("expected different thumbprints for different tokens")
		}
	})

	t.Run("empty token produces non-empty thumbprint", func(t *testing.T) {
		tp := RefreshTokenThumbprint("")
		if tp == "" {
			t.Error("expected non-empty thumbprint even for empty token")
		}
	})

	t.Run("thumbprint is 64 char hex", func(t *testing.T) {
		tp := RefreshTokenThumbprint("test-token")
		if len(tp) != 64 {
			t.Errorf("expected 64-char hex thumbprint, got %d chars", len(tp))
		}
	})
}

func TestRefreshAuthContext(t *testing.T) {
	now := time.Now()
	ctx := RefreshAuthContext{
		AMR:      []string{"pwd"},
		ACR:      "https://schemas.openid.net/pape/policies/2007/06/multi-factor",
		AuthTime: now,
	}

	if len(ctx.AMR) != 1 || ctx.AMR[0] != "pwd" {
		t.Errorf("expected AMR ['pwd'], got %v", ctx.AMR)
	}
	if ctx.ACR != "https://schemas.openid.net/pape/policies/2007/06/multi-factor" {
		t.Errorf("unexpected ACR: %q", ctx.ACR)
	}
	if ctx.AuthTime != now {
		t.Errorf("expected AuthTime %v, got %v", now, ctx.AuthTime)
	}
}
