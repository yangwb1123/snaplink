package conditionalaccess

import (
	"context"
	"testing"
	"time"
)

const sampleBundle = `
policies:
  - name: restrict-admin-access
    priority: 100
    enabled: true
    conditions:
      user.member_of: ["admin"]
      device.managed: false
      risk_score: "> 0.5"
      session.age_seconds: 3600
      authentication.age_seconds: 1800
      session.max_concurrent: 3
    actions:
      require_step_up: mfa
      restrict_scopes: ["admin:read"]
      log: true
  - name: allow-trusted
    priority: 10
    enabled: true
    conditions:
      risk_score: "< 0.2"
    actions:
      allow: true
`

func TestLoadPolicies_ParsesGrammar(t *testing.T) {
	policies, err := LoadPolicies([]byte(sampleBundle))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(policies) != 2 {
		t.Fatalf("got %d policies, want 2", len(policies))
	}
	p := policies[0]
	if p.Name != "restrict-admin-access" || p.Priority != 100 || !p.Enabled {
		t.Errorf("unexpected header: %+v", p)
	}
	if len(p.Conditions.UserMemberOf) != 1 || p.Conditions.UserMemberOf[0] != "admin" {
		t.Errorf("member_of = %v", p.Conditions.UserMemberOf)
	}
	if p.Conditions.DeviceManaged == nil || *p.Conditions.DeviceManaged {
		t.Errorf("device.managed = %v, want false", p.Conditions.DeviceManaged)
	}
	if p.Conditions.RiskScore != "> 0.5" {
		t.Errorf("risk_score = %q", p.Conditions.RiskScore)
	}
	if p.Conditions.SessionAgeSeconds != 3600 || p.Conditions.AuthenticationAgeSeconds != 1800 || p.Conditions.MaxConcurrentSessions != 3 {
		t.Errorf("age conditions = session:%d authentication:%d", p.Conditions.SessionAgeSeconds, p.Conditions.AuthenticationAgeSeconds)
	}
	if p.Actions.RequireStepUp != "mfa" || len(p.Actions.RestrictScopes) != 1 || !p.Actions.Log {
		t.Errorf("actions = %+v", p.Actions)
	}
}

func TestLoadPolicies_LoadedBundleEvaluates(t *testing.T) {
	policies, err := LoadPolicies([]byte(sampleBundle))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// A low-trust (risk 0.9) unmanaged admin trips the step-up policy.
	now := time.Now()
	ac := AccessContext{
		Groups:                  []string{"admin"},
		TrustScore:              0.1,
		TrustScoreKnown:         true,
		DevicePosture:           PostureUnmanaged,
		Now:                     now,
		SessionCreatedAt:        now.Add(-2 * time.Hour),
		AuthTime:                now.Add(-time.Hour),
		ConcurrentSessions:      4,
		ConcurrentSessionsKnown: true,
	}
	d := Decide(Config{}, policies, ac)
	if d.Verdict != VerdictRequireStepUp || d.MatchedPolicy != "restrict-admin-access" {
		t.Fatalf("verdict %q matched %q, want require_step_up/restrict-admin-access", d.Verdict, d.MatchedPolicy)
	}
	if d.StepUpMethod != "mfa" {
		t.Errorf("step-up method = %q, want mfa", d.StepUpMethod)
	}
}

func TestLoadPolicies_RejectsUnknownField(t *testing.T) {
	bad := `
policies:
  - name: p
    enabled: true
    conditions:
      not_a_real_field: true
`
	if _, err := LoadPolicies([]byte(bad)); err == nil {
		t.Fatal("expected an unknown-field parse error")
	}
}

func TestLoadPolicies_RejectsInvalidPolicy(t *testing.T) {
	bad := `
policies:
  - name: p
    enabled: true
    conditions:
      risk_score: "not-a-comparison"
`
	if _, err := LoadPolicies([]byte(bad)); err == nil {
		t.Fatal("expected a validation error for the malformed comparison")
	}
}

func TestLoadInto_PopulatesStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if err := LoadInto(ctx, store, []byte(sampleBundle)); err != nil {
		t.Fatalf("load into: %v", err)
	}
	list, _ := store.List(ctx)
	if len(list) != 2 {
		t.Fatalf("store has %d policies, want 2", len(list))
	}
}
