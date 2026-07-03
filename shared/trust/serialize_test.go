package trust_test

import (
	"testing"

	"github.com/snaplink/sso/shared/trust"
)

func TestSessionMetadata_OffByDefault(t *testing.T) {
	// Zero-value config (the wire-safe default) must add NOTHING.
	got := trust.SessionMetadata(trust.SerializationConfig{}, trust.TrustScore{Value: 0.9})
	if got != nil {
		t.Fatalf("SessionMetadata() = %v, want nil for a disabled config", got)
	}
}

func TestSessionMetadata_EnabledRendersScoreAndReasons(t *testing.T) {
	cfg := trust.SerializationConfig{StampSessionMetadata: true}
	got := trust.SessionMetadata(cfg, trust.TrustScore{Value: 0.756, Reasons: []string{"geo_risk:known_country", "behavior:cold_start"}})
	if got == nil {
		t.Fatal("SessionMetadata() = nil, want a populated map")
	}
	if got["trust_score"] != "0.76" {
		t.Fatalf("trust_score = %q, want 0.76 (rounded)", got["trust_score"])
	}
	if got["trust_reasons"] != "geo_risk:known_country,behavior:cold_start" {
		t.Fatalf("trust_reasons = %q, want comma-joined reasons", got["trust_reasons"])
	}
}

func TestTokenClaim_OffByDefault(t *testing.T) {
	name, value, ok := trust.TokenClaim(trust.SerializationConfig{}, trust.TrustScore{Value: 0.9})
	if ok {
		t.Fatalf("TokenClaim() ok = true, want false for a disabled config (name=%q value=%q)", name, value)
	}
	if name != "" || value != "" {
		t.Fatalf("TokenClaim() = (%q, %q), want empty strings when disabled", name, value)
	}
}

func TestTokenClaim_EnabledUsesDefaultClaimName(t *testing.T) {
	cfg := trust.SerializationConfig{IncludeTokenClaim: true}
	name, value, ok := trust.TokenClaim(cfg, trust.TrustScore{Value: 0.5})
	if !ok {
		t.Fatal("TokenClaim() ok = false, want true")
	}
	if name != trust.DefaultTrustScoreClaim {
		t.Fatalf("name = %q, want %q", name, trust.DefaultTrustScoreClaim)
	}
	if value != "0.50" {
		t.Fatalf("value = %q, want 0.50", value)
	}
}

func TestTokenClaim_EnabledWithCustomClaimName(t *testing.T) {
	cfg := trust.SerializationConfig{IncludeTokenClaim: true, ClaimName: "zt_trust"}
	name, _, ok := trust.TokenClaim(cfg, trust.TrustScore{Value: 0.5})
	if !ok {
		t.Fatal("TokenClaim() ok = false, want true")
	}
	if name != "zt_trust" {
		t.Fatalf("name = %q, want zt_trust", name)
	}
}
