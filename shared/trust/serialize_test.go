package trust

import (
	"testing"
)

func TestClampScore(t *testing.T) {
	tests := []struct {
		input    float64
		expected float64
	}{
		{0.5, 0.5},
		{1.5, 1.0},
		{-0.5, 0.0},
		{0.0, 0.0},
		{1.0, 1.0},
		{0.75, 0.75},
	}

	for _, tc := range tests {
		got := ClampScore(tc.input)
		if got != tc.expected {
			t.Errorf("ClampScore(%f) = %f, want %f", tc.input, got, tc.expected)
		}
	}
}

func TestFormatScore(t *testing.T) {
	tests := []struct {
		input    float64
		expected string
	}{
		{0.5, "0.50"},
		{0.0, "0.00"},
		{1.0, "1.00"},
		{0.12345, "0.12"},
		{0.999, "1.00"},
		{0.001, "0.00"},
	}

	for _, tc := range tests {
		got := formatScore(tc.input)
		if got != tc.expected {
			t.Errorf("formatScore(%f) = %q, want %q", tc.input, got, tc.expected)
		}
	}
}

func TestTokenClaim(t *testing.T) {
	t.Run("no serialization", func(t *testing.T) {
		cfg := SerializationConfig{}
		score := TrustScore{Value: 0.75}
		_, _, ok := TokenClaim(cfg, score)
		if ok {
			t.Error("expected ok=false for empty config")
		}
	})

	t.Run("token claim enabled", func(t *testing.T) {
		cfg := SerializationConfig{
			IncludeTokenClaim: true,
			ClaimName:         "trust_score",
		}
		score := TrustScore{Value: 0.75}
		name, val, ok := TokenClaim(cfg, score)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != "trust_score" {
			t.Errorf("expected name 'trust_score', got %q", name)
		}
		if val != "0.75" {
			t.Errorf("expected value '0.75', got %q", val)
		}
	})

	t.Run("empty claim name falls back to default", func(t *testing.T) {
		cfg := SerializationConfig{
			IncludeTokenClaim: true,
		}
		score := TrustScore{Value: 0.5}
		name, val, ok := TokenClaim(cfg, score)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != DefaultTrustScoreClaim {
			t.Errorf("expected default claim name %q, got %q", DefaultTrustScoreClaim, name)
		}
		if val != "0.50" {
			t.Errorf("expected value '0.50', got %q", val)
		}
	})

	t.Run("custom claim name", func(t *testing.T) {
		cfg := SerializationConfig{
			IncludeTokenClaim: true,
			ClaimName:         "https://sso.example.com/trust",
		}
		score := TrustScore{Value: 0.5}
		name, _, ok := TokenClaim(cfg, score)
		if !ok {
			t.Fatal("expected ok=true")
		}
		if name != "https://sso.example.com/trust" {
			t.Errorf("expected custom claim name, got %q", name)
		}
	})

	t.Run("claim disabled even with name set", func(t *testing.T) {
		cfg := SerializationConfig{
			IncludeTokenClaim: false,
			ClaimName:         "trust_score",
		}
		score := TrustScore{Value: 0.75}
		_, _, ok := TokenClaim(cfg, score)
		if ok {
			t.Error("expected ok=false when IncludeTokenClaim is false")
		}
	})
}

func TestSessionMetadata(t *testing.T) {
	t.Run("disabled returns nil", func(t *testing.T) {
		cfg := SerializationConfig{}
		score := TrustScore{Value: 0.75}
		meta := SessionMetadata(cfg, score)
		if meta != nil {
			t.Errorf("expected nil, got %v", meta)
		}
	})

	t.Run("enabled returns metadata with reasons", func(t *testing.T) {
		cfg := SerializationConfig{
			StampSessionMetadata: true,
		}
		score := TrustScore{Value: 0.8, Reasons: []string{"geo_risk:known", "behavior:cold_start"}}
		meta := SessionMetadata(cfg, score)
		if meta == nil {
			t.Fatal("expected non-nil metadata")
		}
		if meta["trust_score"] != "0.80" {
			t.Errorf("expected trust_score '0.80', got %q", meta["trust_score"])
		}
		if meta["trust_reasons"] == "" {
			t.Error("expected trust_reasons to be non-empty")
		}
		if meta["trust_reasons"] != "geo_risk:known,behavior:cold_start" {
			t.Errorf("unexpected reasons: %q", meta["trust_reasons"])
		}
	})

	t.Run("no reasons", func(t *testing.T) {
		cfg := SerializationConfig{
			StampSessionMetadata: true,
		}
		score := TrustScore{Value: 0.5}
		meta := SessionMetadata(cfg, score)
		if meta == nil {
			t.Fatal("expected non-nil metadata")
		}
		if meta["trust_reasons"] != "" {
			t.Errorf("expected empty reasons, got %q", meta["trust_reasons"])
		}
	})
}

func TestTrustScoreSerializationRoundTrip(t *testing.T) {
	values := []float64{0.0, 0.25, 0.5, 0.75, 1.0}

	cfg := SerializationConfig{
		IncludeTokenClaim: true,
		ClaimName:         "score",
	}

	for _, v := range values {
		score := TrustScore{Value: v}
		name, _, ok := TokenClaim(cfg, score)
		if !ok {
			t.Errorf("TokenClaim(%f) returned ok=false", v)
			continue
		}
		if name != "score" {
			t.Errorf("TokenClaim(%f) name=%q", v, name)
		}
	}
}
