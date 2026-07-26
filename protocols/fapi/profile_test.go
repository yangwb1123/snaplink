package fapi

import (
	"testing"
)

func TestModeString(t *testing.T) {
	tests := []struct {
		mode Mode
		want string
	}{
		{ModeOff, "off"},
		{ModeInspection, "inspection"},
		{ModeEnforce, "enforce"},
	}

	for _, tc := range tests {
		got := tc.mode.String()
		if got != tc.want {
			t.Errorf("Mode(%d).String() = %q, want %q", tc.mode, got, tc.want)
		}
	}
}

func TestFAPIAllowedAlgSet(t *testing.T) {
	algs := FAPIAllowedAlgSet()

	required := []string{"ES256", "ES384", "ES512", "EdDSA"}
	for _, alg := range required {
		if _, ok := algs[alg]; !ok {
			t.Errorf("FAPI should include %q", alg)
		}
	}

	forbidden := []string{"none", "HS256", "RS256"}
	for _, alg := range forbidden {
		if _, ok := algs[alg]; ok {
			t.Errorf("FAPI must NOT include %q", alg)
		}
	}
}

func TestIsFAPIAllowedAlg(t *testing.T) {
	if !IsFAPIAllowedAlg("ES256") {
		t.Error("ES256 should be allowed")
	}
	if !IsFAPIAllowedAlg("EdDSA") {
		t.Error("EdDSA should be allowed")
	}
	if IsFAPIAllowedAlg("none") {
		t.Error("none should NOT be allowed")
	}
	if IsFAPIAllowedAlg("HS256") {
		t.Error("HS256 should NOT be allowed")
	}
}

func TestExtractJWTAlg(t *testing.T) {
	t.Run("valid ES256 JWT", func(t *testing.T) {
		compact := "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.payload.signature"
		alg := ExtractJWTAlg(compact)
		if alg != "ES256" {
			t.Errorf("expected 'ES256', got %q", alg)
		}
	})

	t.Run("valid EdDSA JWT", func(t *testing.T) {
		compact := "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.payload.signature"
		alg := ExtractJWTAlg(compact)
		if alg != "EdDSA" {
			t.Errorf("expected 'EdDSA', got %q", alg)
		}
	})

	t.Run("empty string returns empty", func(t *testing.T) {
		if alg := ExtractJWTAlg(""); alg != "" {
			t.Errorf("expected empty, got %q", alg)
		}
	})

	t.Run("invalid segments returns empty", func(t *testing.T) {
		if alg := ExtractJWTAlg("only-two"); alg != "" {
			t.Errorf("expected empty for invalid segments, got %q", alg)
		}
	})
}

func TestViolationFields(t *testing.T) {
	v := Violation{
		RuleID:   "FAPI-2.0-1",
		Detail:   "alg=none not allowed",
		ClientID: "client-1",
	}

	if v.RuleID != "FAPI-2.0-1" {
		t.Errorf("expected 'FAPI-2.0-1', got %q", v.RuleID)
	}
	if v.Detail != "alg=none not allowed" {
		t.Errorf("unexpected detail: %q", v.Detail)
	}
	if v.ClientID != "client-1" {
		t.Errorf("expected 'client-1', got %q", v.ClientID)
	}
}

func TestFAPIAllowedAlgSetCardinality(t *testing.T) {
	algs := FAPIAllowedAlgSet()
	if len(algs) < 4 {
		t.Errorf("expected at least 4 FAPI algs, got %d", len(algs))
	}
}
