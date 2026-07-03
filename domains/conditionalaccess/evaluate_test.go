package conditionalaccess

import (
	"context"
	"errors"
	"testing"
	"time"
)

func boolPtr(b bool) *bool { return &b }

// knownTrust is the common "signal present" access context helper.
func knownTrust(score float64) AccessContext {
	return AccessContext{TrustScore: score, TrustScoreKnown: true, DevicePosture: PostureManaged}
}

func policy(name string, prio int, c Conditions, a Actions) Policy {
	return Policy{Name: name, Priority: prio, Enabled: true, Conditions: c, Actions: a}
}

func TestDecide_DefaultAllowWhenNoPolicies(t *testing.T) {
	d := Decide(Config{}, nil, knownTrust(0.9))
	if d.Verdict != VerdictAllow {
		t.Fatalf("verdict = %q, want allow", d.Verdict)
	}
	if d.MatchedPolicy != "" {
		t.Errorf("matched policy = %q, want empty", d.MatchedPolicy)
	}
}

func TestDecide_DefaultDeny(t *testing.T) {
	d := Decide(Config{DefaultDeny: true}, nil, knownTrust(0.9))
	if d.Verdict != VerdictDeny {
		t.Fatalf("verdict = %q, want deny", d.Verdict)
	}
}

func TestDecide_ConditionGrammar(t *testing.T) {
	now := time.Date(2026, 7, 3, 10, 30, 0, 0, time.UTC) // 10:30 UTC
	tests := []struct {
		name  string
		cond  Conditions
		ac    AccessContext
		match bool
	}{
		{
			name:  "member_of any-of hit",
			cond:  Conditions{UserMemberOf: []string{"admin", "ops"}},
			ac:    AccessContext{Groups: []string{"ops"}, TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "member_of miss",
			cond:  Conditions{UserMemberOf: []string{"admin"}},
			ac:    AccessContext{Groups: []string{"user"}, TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: false,
		},
		{
			name:  "device.managed true hits managed",
			cond:  Conditions{DeviceManaged: boolPtr(true)},
			ac:    AccessContext{TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "device.managed false hits unmanaged",
			cond:  Conditions{DeviceManaged: boolPtr(false)},
			ac:    AccessContext{TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureUnmanaged},
			match: true,
		},
		{
			name:  "device.managed false hits unknown posture",
			cond:  Conditions{DeviceManaged: boolPtr(false)},
			ac:    AccessContext{TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureUnknown},
			match: true,
		},
		{
			name:  "device.managed true misses unknown posture",
			cond:  Conditions{DeviceManaged: boolPtr(true)},
			ac:    AccessContext{TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureUnknown},
			match: false,
		},
		{
			name:  "risk_score gt hit (low trust -> high risk)",
			cond:  Conditions{RiskScore: "> 0.5"},
			ac:    knownTrust(0.2), // risk 0.8
			match: true,
		},
		{
			name:  "risk_score gt miss (high trust -> low risk)",
			cond:  Conditions{RiskScore: "> 0.5"},
			ac:    knownTrust(0.9), // risk 0.1
			match: false,
		},
		{
			name:  "geo.in hit case-insensitive",
			cond:  Conditions{GeoIn: []string{"US", "CA"}},
			ac:    AccessContext{Country: "us", TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "geo.not_in hit",
			cond:  Conditions{GeoNotIn: []string{"CN"}},
			ac:    AccessContext{Country: "US", TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "geo.not_in miss (country is in the denylist)",
			cond:  Conditions{GeoNotIn: []string{"CN"}},
			ac:    AccessContext{Country: "CN", TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: false,
		},
		{
			name:  "geo unknown country never matches (fail-open)",
			cond:  Conditions{GeoNotIn: []string{"CN"}},
			ac:    AccessContext{Country: "", TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: false,
		},
		{
			name:  "time window hit",
			cond:  Conditions{TimeAfter: "08:00", TimeBefore: "18:00"},
			ac:    AccessContext{Now: now, TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "time window miss",
			cond:  Conditions{TimeAfter: "18:00", TimeBefore: "22:00"},
			ac:    AccessContext{Now: now, TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: false,
		},
		{
			name:  "time window wrapping midnight hit",
			cond:  Conditions{TimeAfter: "22:00", TimeBefore: "06:00"},
			ac:    AccessContext{Now: time.Date(2026, 7, 3, 2, 0, 0, 0, time.UTC), TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: true,
		},
		{
			name:  "time window with zero clock never matches",
			cond:  Conditions{TimeAfter: "08:00", TimeBefore: "18:00"},
			ac:    AccessContext{TrustScoreKnown: true, TrustScore: 0.9, DevicePosture: PostureManaged},
			match: false,
		},
		{
			name:  "AND of multiple conditions all hit",
			cond:  Conditions{UserMemberOf: []string{"admin"}, RiskScore: ">= 0.5", DeviceManaged: boolPtr(false)},
			ac:    AccessContext{Groups: []string{"admin"}, TrustScore: 0.2, TrustScoreKnown: true, DevicePosture: PostureUnmanaged},
			match: true,
		},
		{
			name:  "AND of multiple conditions one miss",
			cond:  Conditions{UserMemberOf: []string{"admin"}, RiskScore: ">= 0.5"},
			ac:    AccessContext{Groups: []string{"admin"}, TrustScore: 0.9, TrustScoreKnown: true, DevicePosture: PostureManaged},
			match: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			p := policy("p", 0, tc.cond, Actions{Deny: true})
			d := Decide(Config{}, []Policy{p}, tc.ac)
			gotMatch := d.MatchedPolicy == "p"
			if gotMatch != tc.match {
				t.Fatalf("match = %v (verdict %q), want %v", gotMatch, d.Verdict, tc.match)
			}
		})
	}
}

func TestDecide_ActionResolution(t *testing.T) {
	catchAll := Conditions{}
	tests := []struct {
		name    string
		actions Actions
		want    Verdict
		stepUp  string
		scopes  []string
		log     bool
	}{
		{"allow", Actions{Allow: true}, VerdictAllow, "", nil, false},
		{"deny", Actions{Deny: true}, VerdictDeny, "", nil, false},
		{"require_step_up", Actions{RequireStepUp: "mfa"}, VerdictRequireStepUp, "mfa", nil, false},
		{"deny beats step_up", Actions{Deny: true, RequireStepUp: "mfa"}, VerdictDeny, "", nil, false},
		{"restrict_scopes only implies allow", Actions{RestrictScopes: []string{"admin:read"}}, VerdictAllow, "", []string{"admin:read"}, false},
		{"log modifier", Actions{Allow: true, Log: true}, VerdictAllow, "", nil, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := Decide(Config{}, []Policy{policy("p", 0, catchAll, tc.actions)}, knownTrust(0.9))
			if d.Verdict != tc.want {
				t.Errorf("verdict = %q, want %q", d.Verdict, tc.want)
			}
			if d.StepUpMethod != tc.stepUp {
				t.Errorf("step-up = %q, want %q", d.StepUpMethod, tc.stepUp)
			}
			if tc.scopes != nil && (len(d.RestrictScopes) != 1 || d.RestrictScopes[0] != tc.scopes[0]) {
				t.Errorf("restrict scopes = %v, want %v", d.RestrictScopes, tc.scopes)
			}
			if d.Log != tc.log {
				t.Errorf("log = %v, want %v", d.Log, tc.log)
			}
		})
	}
}

func TestDecide_PriorityOrdering(t *testing.T) {
	// Two catch-all policies; the higher-priority one wins.
	low := policy("low", 1, Conditions{}, Actions{Allow: true})
	high := policy("high", 10, Conditions{}, Actions{Deny: true})
	d := Decide(Config{}, []Policy{low, high}, knownTrust(0.9))
	if d.MatchedPolicy != "high" || d.Verdict != VerdictDeny {
		t.Fatalf("matched %q verdict %q, want high/deny", d.MatchedPolicy, d.Verdict)
	}
}

func TestDecide_SpecificityTieBreak(t *testing.T) {
	// Same priority: the more-specific policy (more conditions) is evaluated
	// first. Both match here, so the specific one must win.
	broad := policy("broad", 5, Conditions{}, Actions{Allow: true})
	specific := policy("specific", 5, Conditions{UserMemberOf: []string{"admin"}, RiskScore: ">= 0"}, Actions{Deny: true})
	ac := AccessContext{Groups: []string{"admin"}, TrustScore: 0.9, TrustScoreKnown: true, DevicePosture: PostureManaged}
	d := Decide(Config{}, []Policy{broad, specific}, ac)
	if d.MatchedPolicy != "specific" {
		t.Fatalf("matched %q, want specific", d.MatchedPolicy)
	}
}

func TestDecide_DisabledPolicySkipped(t *testing.T) {
	p := policy("p", 10, Conditions{}, Actions{Deny: true})
	p.Enabled = false
	d := Decide(Config{}, []Policy{p}, knownTrust(0.9))
	if d.Verdict != VerdictAllow || d.MatchedPolicy != "" {
		t.Fatalf("disabled policy was enforced: matched %q verdict %q", d.MatchedPolicy, d.Verdict)
	}
}

func TestDecide_DryRunReportedNotEnforced(t *testing.T) {
	dry := policy("staged", 10, Conditions{}, Actions{Deny: true})
	dry.DryRun = true
	live := policy("live", 5, Conditions{}, Actions{Allow: true})
	d := Decide(Config{}, []Policy{dry, live}, knownTrust(0.9))
	if d.MatchedPolicy != "live" || d.Verdict != VerdictAllow {
		t.Fatalf("dry-run policy enforced: matched %q verdict %q", d.MatchedPolicy, d.Verdict)
	}
	if len(d.DryRunMatches) != 1 || d.DryRunMatches[0] != "staged" {
		t.Fatalf("dry-run matches = %v, want [staged]", d.DryRunMatches)
	}
}

func TestDecide_FailClosedOnMalformedCondition(t *testing.T) {
	// A malformed comparison the evaluator cannot parse must DENY (fail-closed
	// for the policy verdict), not be silently skipped.
	bad := Policy{Name: "bad", Enabled: true, Priority: 10, Conditions: Conditions{RiskScore: "totally-bogus"}, Actions: Actions{Allow: true}}
	d := Decide(Config{}, []Policy{bad}, knownTrust(0.9))
	if d.Verdict != VerdictDeny {
		t.Fatalf("verdict = %q, want deny (fail-closed)", d.Verdict)
	}
	if d.MatchedPolicy != "bad" {
		t.Errorf("matched policy = %q, want bad", d.MatchedPolicy)
	}
}

func TestDecide_FailOpenOnMissingTrustSignal(t *testing.T) {
	// A deny policy that would only fire at very high risk. With the trust
	// score MISSING, the engine degrades to the floor (0.3 -> risk 0.7) rather
	// than denying outright: risk 0.7 is not > 0.9, so the deny does NOT fire.
	p := policy("p", 0, Conditions{RiskScore: "> 0.9"}, Actions{Deny: true})
	ac := AccessContext{TrustScoreKnown: false, DevicePosture: PostureManaged}
	d := Decide(Config{}, []Policy{p}, ac)
	if d.Verdict != VerdictAllow {
		t.Fatalf("verdict = %q, want allow (fail-open on missing signal)", d.Verdict)
	}
	if !d.Degraded {
		t.Error("expected Degraded=true when the trust score is missing")
	}
	if d.EffectiveTrust != DefaultDegradedTrust {
		t.Errorf("effective trust = %v, want %v", d.EffectiveTrust, DefaultDegradedTrust)
	}
}

func TestDecide_UnknownPostureCapsTrust(t *testing.T) {
	// A high real trust score is capped down to the floor when the device
	// won't report posture (privacy-respecting degradation).
	p := policy("p", 0, Conditions{RiskScore: "> 0.5"}, Actions{Deny: true})
	ac := AccessContext{TrustScore: 0.95, TrustScoreKnown: true, DevicePosture: PostureUnknown}
	d := Decide(Config{}, []Policy{p}, ac)
	if d.EffectiveTrust != DefaultDegradedTrust {
		t.Fatalf("effective trust = %v, want capped to %v", d.EffectiveTrust, DefaultDegradedTrust)
	}
	// risk = 1 - 0.3 = 0.7 > 0.5 -> the deny fires.
	if d.Verdict != VerdictDeny {
		t.Errorf("verdict = %q, want deny after posture cap", d.Verdict)
	}
	if !d.Degraded {
		t.Error("expected Degraded=true on unknown posture")
	}
}

func TestDecide_CustomDegradedFloorRespected(t *testing.T) {
	p := policy("p", 0, Conditions{RiskScore: "> 0.5"}, Actions{Deny: true})
	ac := AccessContext{TrustScoreKnown: false, DevicePosture: PostureManaged}
	// Floor 0.8 -> risk 0.2, below the 0.5 threshold -> allow.
	d := Decide(Config{DegradedTrust: 0.8}, []Policy{p}, ac)
	if d.EffectiveTrust != 0.8 {
		t.Fatalf("effective trust = %v, want 0.8", d.EffectiveTrust)
	}
	if d.Verdict != VerdictAllow {
		t.Errorf("verdict = %q, want allow with a high floor", d.Verdict)
	}
}

func TestEngine_EvaluateStoreErrorFallsBackToDefault(t *testing.T) {
	e := NewEngine(errStore{}, Config{DefaultDeny: true})
	d, err := e.Evaluate(context.Background(), knownTrust(0.9))
	if err == nil {
		t.Fatal("expected the store error to be surfaced")
	}
	if d.Verdict != VerdictDeny {
		t.Errorf("verdict = %q, want deny (DefaultDeny fallback)", d.Verdict)
	}
	if !d.Degraded {
		t.Error("expected Degraded=true on store outage")
	}
}

func TestEngine_EvaluateUsesStorePolicies(t *testing.T) {
	store := NewMemoryStore()
	if err := store.Put(context.Background(), policy("deny-low-trust", 0, Conditions{RiskScore: "> 0.5"}, Actions{Deny: true})); err != nil {
		t.Fatalf("put: %v", err)
	}
	e := NewEngine(store, Config{})
	d, err := e.Evaluate(context.Background(), knownTrust(0.1)) // risk 0.9
	if err != nil {
		t.Fatalf("evaluate: %v", err)
	}
	if d.Verdict != VerdictDeny {
		t.Errorf("verdict = %q, want deny", d.Verdict)
	}
}

func TestParseComparison(t *testing.T) {
	tests := []struct {
		expr    string
		op      string
		thresh  float64
		wantErr bool
	}{
		{">0.5", ">", 0.5, false},
		{">= 0.5", ">=", 0.5, false},
		{"<0.3", "<", 0.3, false},
		{"<=  0.99", "<=", 0.99, false},
		{"== 0", "==", 0, false},
		{"!= 1", "!=", 1, false},
		{"0.5", "", 0, true},   // no operator
		{"> abc", "", 0, true}, // bad number
		{"", "", 0, true},
	}
	for _, tc := range tests {
		op, th, err := parseComparison(tc.expr)
		if (err != nil) != tc.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", tc.expr, err, tc.wantErr)
			continue
		}
		if tc.wantErr {
			continue
		}
		if op != tc.op || th != tc.thresh {
			t.Errorf("%q: got (%q,%v), want (%q,%v)", tc.expr, op, th, tc.op, tc.thresh)
		}
	}
}

// errStore is a Store whose List always fails, for the outage-path test.
type errStore struct{}

func (errStore) List(context.Context) ([]Policy, error)            { return nil, errors.New("boom") }
func (errStore) Get(context.Context, string) (Policy, bool, error) { return Policy{}, false, nil }
func (errStore) Put(context.Context, Policy) error                 { return nil }
func (errStore) Delete(context.Context, string) error              { return nil }
