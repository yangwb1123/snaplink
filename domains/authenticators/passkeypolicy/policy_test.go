package passkeypolicy

import "testing"

func TestValid(t *testing.T) {
	cases := []struct {
		f    PromptFrequency
		want bool
	}{
		{PromptNever, true},
		{PromptOnce, true},
		{PromptPeriodic, true},
		{"", false},
		{"onec", false},
		{"NEVER", false}, // case-sensitive: callers normalize before assigning
	}
	for _, c := range cases {
		if got := c.f.Valid(); got != c.want {
			t.Errorf("PromptFrequency(%q).Valid() = %v, want %v", c.f, got, c.want)
		}
	}
}

// TestDecide_OffByDefault proves the zero-value Policy (RequirePasskey
// false) never nudges regardless of signals — the byte-identical-off
// contract every caller (interfaces/sso) relies on.
func TestDecide_OffByDefault(t *testing.T) {
	var p Policy // zero value
	cases := []Signals{
		{},
		{HasDiscoverableCredential: false, RiskKnown: true, RiskScore: 1.0},
		{HasDiscoverableCredential: true},
	}
	for _, s := range cases {
		if Decide(p, s) {
			t.Errorf("Decide(off-policy, %+v) = true, want false", s)
		}
	}
}

// TestDecide_HasCredentialNeverNudges proves a user who already satisfies
// the policy is never nudged, regardless of frequency.
func TestDecide_HasCredentialNeverNudges(t *testing.T) {
	for _, freq := range []PromptFrequency{PromptOnce, PromptPeriodic, PromptNever, ""} {
		p := Policy{RequirePasskey: true, PromptFrequency: freq}
		s := Signals{HasDiscoverableCredential: true, RiskKnown: true, RiskScore: 1.0}
		if Decide(p, s) {
			t.Errorf("Decide(freq=%q, has-credential) = true, want false", freq)
		}
	}
}

func TestDecide_PromptNever(t *testing.T) {
	p := Policy{RequirePasskey: true, PromptFrequency: PromptNever}
	s := Signals{HasDiscoverableCredential: false}
	if Decide(p, s) {
		t.Error("Decide(PromptNever, missing credential) = true, want false")
	}
}

// TestDecide_PromptOnceAndZeroValue proves PromptOnce nudges every login
// missing a credential, and that an empty/invalid PromptFrequency degrades
// to identical behavior (the "unset must not silently suppress the feature"
// contract).
func TestDecide_PromptOnceAndZeroValue(t *testing.T) {
	for _, freq := range []PromptFrequency{PromptOnce, "", "garbage-typo"} {
		p := Policy{RequirePasskey: true, PromptFrequency: freq}
		s := Signals{HasDiscoverableCredential: false}
		if !Decide(p, s) {
			t.Errorf("Decide(freq=%q, missing credential) = false, want true", freq)
		}
	}
}

func TestDecide_PromptPeriodic(t *testing.T) {
	p := Policy{RequirePasskey: true, PromptFrequency: PromptPeriodic}

	// Unknown risk (no scorer wired / scorer errored) degrades to "once"
	// behavior: still nudge, fail-open toward MORE nudging.
	if !Decide(p, Signals{HasDiscoverableCredential: false, RiskKnown: false}) {
		t.Error("Decide(periodic, risk unknown) = false, want true (degrade to once)")
	}

	// Known LOW risk: throttled — no nudge.
	if Decide(p, Signals{HasDiscoverableCredential: false, RiskKnown: true, RiskScore: HighRiskThreshold - 0.01}) {
		t.Error("Decide(periodic, low risk) = true, want false (throttled)")
	}

	// Known HIGH risk: nudge unconditionally.
	if !Decide(p, Signals{HasDiscoverableCredential: false, RiskKnown: true, RiskScore: HighRiskThreshold}) {
		t.Error("Decide(periodic, risk == threshold) = false, want true")
	}
	if !Decide(p, Signals{HasDiscoverableCredential: false, RiskKnown: true, RiskScore: 1.0}) {
		t.Error("Decide(periodic, max risk) = false, want true")
	}
}
