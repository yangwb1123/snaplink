package threataction

import (
	"testing"
)

func TestThreatPolicy_Match(t *testing.T) {
	t.Run("disabled policy never matches", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: false,
			Type:    "impossible_travel",
			Action:  ActionSuspend,
		}
		threat := Threat{Type: "impossible_travel", Severity: SeverityCritical}
		if p.Match(threat) {
			t.Error("disabled policy should not match")
		}
	})

	t.Run("exact type match", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel",
			Action:  ActionSuspend,
		}
		tests := []struct {
			threatType string
			want       bool
		}{
			{"impossible_travel", true},
			{"velocity_burst", false},
			{"", false},
		}
		for _, tt := range tests {
			got := p.Match(Threat{Type: tt.threatType, Severity: SeverityCritical})
			if got != tt.want {
				t.Errorf("type %q: got %v, want %v", tt.threatType, got, tt.want)
			}
		}
	})

	t.Run("empty type matches all", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "catchall",
			Enabled: true,
			Type:    "",
			Action:  ActionNoop,
		}
		if !p.Match(Threat{Type: "anything", Severity: SeverityInfo}) {
			t.Error("empty type should match any threat type")
		}
	})

	t.Run("wildcard type: prefix match", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel/*",
			Action:  ActionSuspend,
		}
		tests := []struct {
			threatType string
			want       bool
		}{
			{"impossible_travel/critical", true},
			{"impossible_travel/warn", true},
			// No "/" boundary in the actual type: the literal prefix
			// "impossible_travel/" (trailing "*" stripped) does not match.
			{"impossible_travelXYZ", false},
			{"impossible_travel", false}, // shorter than the literal prefix
			{"velocity_burst", false},
		}
		for _, tt := range tests {
			got := p.Match(Threat{Type: tt.threatType, Severity: SeverityCritical})
			if got != tt.want {
				t.Errorf("type %q: got %v, want %v", tt.threatType, got, tt.want)
			}
		}
	})

	t.Run("wildcard type: prefix match has no implicit boundary", func(t *testing.T) {
		// Prefix matching is pure string-prefix: a pattern with no boundary
		// character of its own (e.g. "/") matches anything sharing that
		// literal prefix, including a run-on suffix. Contrast with the
		// "impossible_travel/*" case above, where the "/" IS the boundary
		// and is supplied by the operator, not inferred by matchType.
		p := ThreatPolicy{Name: "test", Enabled: true, Type: "impossible_travel*", Action: ActionSuspend}
		if !p.Match(Threat{Type: "impossible_travelXYZ", Severity: SeverityCritical}) {
			t.Error("pure prefix pattern without a boundary character should match a run-on suffix")
		}
	})

	t.Run("wildcard type: suffix match", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "*_burst",
			Action:  ActionSuspend,
		}
		tests := []struct {
			threatType string
			want       bool
		}{
			{"velocity_burst", true},
			{"rate_burst", true},
			{"burst", false},  // shorter than the literal suffix
			{"xburst", false}, // does not end in "_burst"
			{"impossible_travel", false},
		}
		for _, tt := range tests {
			got := p.Match(Threat{Type: tt.threatType, Severity: SeverityCritical})
			if got != tt.want {
				t.Errorf("type %q: got %v, want %v", tt.threatType, got, tt.want)
			}
		}
	})

	t.Run("wildcard type: bare * matches any type, same as empty", func(t *testing.T) {
		p := ThreatPolicy{Name: "test", Enabled: true, Type: "*", Action: ActionSuspend}
		for _, tt := range []string{"impossible_travel", "velocity_burst", "anything", ""} {
			if !p.Match(Threat{Type: tt, Severity: SeverityCritical}) {
				t.Errorf("bare \"*\" should match type %q", tt)
			}
		}
	})

	t.Run("malformed type pattern (asterisk mid-string) falls back to literal match", func(t *testing.T) {
		p := ThreatPolicy{Name: "test", Enabled: true, Type: "foo*bar", Action: ActionSuspend}
		if p.Match(Threat{Type: "foobar", Severity: SeverityCritical}) {
			t.Error("mid-string asterisk must NOT be glob-expanded to allow any infix")
		}
		if p.Match(Threat{Type: "foo", Severity: SeverityCritical}) {
			t.Error("mid-string asterisk must NOT be treated as a wildcard")
		}
		// The only way to match a malformed pattern is its own literal
		// string, asterisk included -- proving the fallback is a safe
		// literal comparison, not a crash or an accidental broad match.
		if !p.Match(Threat{Type: "foo*bar", Severity: SeverityCritical}) {
			t.Error("malformed pattern should still literal-match its own exact string")
		}
	})

	t.Run("malformed type pattern (multiple asterisks) falls back to literal match", func(t *testing.T) {
		p := ThreatPolicy{Name: "test", Enabled: true, Type: "*foo*", Action: ActionSuspend}
		if p.Match(Threat{Type: "xfoox", Severity: SeverityCritical}) {
			t.Error("more than one asterisk must NOT be glob-expanded")
		}
		if p.Match(Threat{Type: "foo", Severity: SeverityCritical}) {
			t.Error("more than one asterisk must NOT match a plain substring")
		}
		if !p.Match(Threat{Type: "*foo*", Severity: SeverityCritical}) {
			t.Error("malformed pattern should still literal-match its own exact string")
		}
	})

	t.Run("wildcard type match combined with severity mismatch still fails overall Match", func(t *testing.T) {
		// Proves the wildcard change is confined to the Type clause: a
		// Type-wildcard match does NOT short-circuit the rest of Match --
		// MatchesSeverity and Conditions.Match must still ALL pass for an
		// overall match.
		p := ThreatPolicy{
			Name:     "test",
			Enabled:  true,
			Type:     "impossible_travel/*",
			Severity: SeverityCritical,
			Action:   ActionSuspend,
		}
		threat := Threat{Type: "impossible_travel/anything", Severity: SeverityWarn}
		if p.Match(threat) {
			t.Error("Type wildcard matched but Severity did not -- overall Match must be false")
		}
		// Sanity: the same policy DOES match once severity also lines up.
		threat.Severity = SeverityCritical
		if !p.Match(threat) {
			t.Error("expected match when both Type wildcard and Severity line up")
		}
	})

	t.Run("severity filter empty matches all", func(t *testing.T) {
		p := ThreatPolicy{
			Name:     "test",
			Enabled:  true,
			Type:     "impossible_travel",
			Severity: "",
			Action:   ActionSuspend,
		}
		for _, s := range []string{SeverityInfo, SeverityWarn, SeverityCritical} {
			if !p.Match(Threat{Type: "impossible_travel", Severity: s}) {
				t.Errorf("empty severity should match %q", s)
			}
		}
	})

	t.Run("severity filter exact match", func(t *testing.T) {
		p := ThreatPolicy{
			Name:     "test",
			Enabled:  true,
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Action:   ActionSuspend,
		}
		if !p.Match(Threat{Type: "impossible_travel", Severity: SeverityCritical}) {
			t.Error("should match critical")
		}
		if p.Match(Threat{Type: "impossible_travel", Severity: SeverityWarn}) {
			t.Error("should not match warn")
		}
	})

	t.Run("severity filter warn+critical syntax", func(t *testing.T) {
		p := ThreatPolicy{
			Name:     "test",
			Enabled:  true,
			Type:     "impossible_travel",
			Severity: "warn+critical",
			Action:   ActionSuspend,
		}
		if !p.Match(Threat{Type: "impossible_travel", Severity: SeverityCritical}) {
			t.Error("should match critical")
		}
		if !p.Match(Threat{Type: "impossible_travel", Severity: SeverityWarn}) {
			t.Error("should match warn")
		}
		if p.Match(Threat{Type: "impossible_travel", Severity: SeverityInfo}) {
			t.Error("should not match info")
		}
	})

	t.Run("conditions: exists", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel",
			Action:  ActionSuspend,
			Conditions: ThreatConditions{
				Key:      "distance_km",
				Operator: "exists",
			},
		}
		if !p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{"distance_km": "5000"},
		}) {
			t.Error("should match when evidence key exists")
		}
		if p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{},
		}) {
			t.Error("should not match when evidence key missing")
		}
	})

	t.Run("conditions: eq", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel",
			Action:  ActionSuspend,
			Conditions: ThreatConditions{
				Key:      "distance_km",
				Operator: "eq",
				Value:    "5000",
			},
		}
		if !p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{"distance_km": "5000"},
		}) {
			t.Error("should match when value equals")
		}
		if p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{"distance_km": "9999"},
		}) {
			t.Error("should not match when value differs")
		}
	})

	t.Run("conditions: gt numeric", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel",
			Action:  ActionSuspend,
			Conditions: ThreatConditions{
				Key:      "distance_km",
				Operator: "gt",
				Value:    "1000",
			},
		}
		tests := []struct {
			val  string
			want bool
		}{
			{"5000", true},
			{"1001", true},
			{"1000", false},
			{"999", false},
			{"0", false},
		}
		for _, tt := range tests {
			got := p.Match(Threat{
				Type:     "impossible_travel",
				Severity: SeverityCritical,
				Evidence: map[string]string{"distance_km": tt.val},
			})
			if got != tt.want {
				t.Errorf("distance_km=%q: got %v, want %v", tt.val, got, tt.want)
			}
		}
	})

	t.Run("conditions: lt numeric", func(t *testing.T) {
		p := ThreatPolicy{
			Name:    "test",
			Enabled: true,
			Type:    "impossible_travel",
			Action:  ActionNotify,
			Conditions: ThreatConditions{
				Key:      "distance_km",
				Operator: "lt",
				Value:    "100",
			},
		}
		tests := []struct {
			val  string
			want bool
		}{
			{"50", true},
			{"99", true},
			{"100", false},
			{"500", false},
		}
		for _, tt := range tests {
			got := p.Match(Threat{
				Type:     "impossible_travel",
				Severity: SeverityWarn,
				Evidence: map[string]string{"distance_km": tt.val},
			})
			if got != tt.want {
				t.Errorf("distance_km=%q: got %v, want %v", tt.val, got, tt.want)
			}
		}
	})

	t.Run("full match: type + severity + conditions", func(t *testing.T) {
		p := ThreatPolicy{
			Name:     "strict",
			Enabled:  true,
			Type:     "impossible_travel",
			Severity: "critical",
			Action:   ActionSuspend,
			Conditions: ThreatConditions{
				Key:      "distance_km",
				Operator: "gt",
				Value:    "5000",
			},
		}
		// All conditions met.
		if !p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{"distance_km": "10000"},
		}) {
			t.Error("should match when all conditions met")
		}
		// Wrong severity.
		if p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityWarn,
			Evidence: map[string]string{"distance_km": "10000"},
		}) {
			t.Error("should not match with wrong severity")
		}
		// Evidence value too low.
		if p.Match(Threat{
			Type:     "impossible_travel",
			Severity: SeverityCritical,
			Evidence: map[string]string{"distance_km": "100"},
		}) {
			t.Error("should not match when evidence below threshold")
		}
	})
}

func TestThreatPolicy_MatchesSeverity(t *testing.T) {
	t.Run("empty matches any", func(t *testing.T) {
		p := ThreatPolicy{}
		if !p.MatchesSeverity(SeverityInfo) {
			t.Error("empty severity should match info")
		}
		if !p.MatchesSeverity(SeverityCritical) {
			t.Error("empty severity should match critical")
		}
	})

	t.Run("exact", func(t *testing.T) {
		p := ThreatPolicy{Severity: SeverityCritical}
		if !p.MatchesSeverity(SeverityCritical) {
			t.Error("should match critical")
		}
		if p.MatchesSeverity(SeverityWarn) {
			t.Error("should not match warn")
		}
	})

	t.Run("combined", func(t *testing.T) {
		p := ThreatPolicy{Severity: "warn+critical"}
		if !p.MatchesSeverity(SeverityCritical) {
			t.Error("should match critical")
		}
		if !p.MatchesSeverity(SeverityWarn) {
			t.Error("should match warn")
		}
		if p.MatchesSeverity(SeverityInfo) {
			t.Error("should not match info")
		}
	})
}

func TestThreatConditions_Match(t *testing.T) {
	t.Run("empty key is unconditional", func(t *testing.T) {
		tc := ThreatConditions{}
		if !tc.Match(Threat{}) {
			t.Error("empty conditions should always match")
		}
	})

	t.Run("exists operator", func(t *testing.T) {
		tc := ThreatConditions{Key: "risk_score", Operator: "exists"}
		if !tc.Match(Threat{Evidence: map[string]string{"risk_score": "95"}}) {
			t.Error("should match when key exists")
		}
		if tc.Match(Threat{Evidence: map[string]string{}}) {
			t.Error("should not match when key missing")
		}
	})

	t.Run("unknown operator falls back to existence check", func(t *testing.T) {
		tc := ThreatConditions{Key: "foo", Operator: "unknown", Value: "bar"}
		if !tc.Match(Threat{Evidence: map[string]string{"foo": "bar"}}) {
			t.Error("unknown operator should check existence")
		}
		if tc.Match(Threat{Evidence: map[string]string{}}) {
			t.Error("unknown operator should not match missing key")
		}
	})

	// Regression coverage for the removed lexicographic-comparison fallback:
	// "gt"/"lt" used to fall back to a plain Go string comparison whenever
	// either side failed to parse as a float, which is a wrong-shaped
	// answer for a numeric operator (e.g. "9abc" > "100" was true
	// lexicographically -- comparing the leading '9' byte to '1' -- even
	// though "9abc" isn't a number greater than 100 at all). These cases
	// prove the fix: non-numeric input on EITHER side now returns false
	// instead of an unpredictable byte-ordering result.
	t.Run("gt: non-numeric evidence value no longer lexicographically compares", func(t *testing.T) {
		tc := ThreatConditions{Key: "k", Operator: "gt", Value: "100"}
		// Old code: strconv.ParseFloat("9abc", 64) fails -> fallback to
		// "9abc" > "100" (string compare) -> true (WRONG: "9abc" is not a
		// number, let alone one greater than 100).
		if tc.Match(Threat{Evidence: map[string]string{"k": "9abc"}}) {
			t.Error("non-numeric evidence value must not match \"gt\" via string fallback")
		}
	})

	t.Run("gt: non-numeric Value no longer lexicographically compares", func(t *testing.T) {
		tc := ThreatConditions{Key: "k", Operator: "gt", Value: "100abc"}
		// Old code: strconv.ParseFloat("100abc", 64) fails -> fallback to
		// "9" > "100abc" (string compare) -> true (WRONG: '9' > '1' as
		// bytes, but "100abc" isn't a valid threshold to compare against
		// at all, and 9 is certainly not "greater than" a non-number).
		if tc.Match(Threat{Evidence: map[string]string{"k": "9"}}) {
			t.Error("non-numeric Value must not match \"gt\" via string fallback")
		}
	})

	t.Run("lt: non-numeric Value no longer lexicographically compares", func(t *testing.T) {
		tc := ThreatConditions{Key: "k", Operator: "lt", Value: "abc"}
		// Old code: strconv.ParseFloat("abc", 64) fails -> fallback to
		// "5" < "abc" (string compare) -> true (WRONG: "abc" is not a
		// numeric threshold, so "less than abc" is meaningless — yet the
		// old code confidently answered true).
		if tc.Match(Threat{Evidence: map[string]string{"k": "5"}}) {
			t.Error("non-numeric Value must not match \"lt\" via string fallback")
		}
	})

	t.Run("gt/lt still compare numerically when both sides parse", func(t *testing.T) {
		gt := ThreatConditions{Key: "k", Operator: "gt", Value: "100"}
		if !gt.Match(Threat{Evidence: map[string]string{"k": "101"}}) {
			t.Error("101 should be > 100")
		}
		if gt.Match(Threat{Evidence: map[string]string{"k": "9"}}) {
			t.Error("9 should NOT be > 100 (numerically) -- must not regress to a true positive")
		}
		lt := ThreatConditions{Key: "k", Operator: "lt", Value: "100"}
		if !lt.Match(Threat{Evidence: map[string]string{"k": "9"}}) {
			t.Error("9 should be < 100")
		}
		if lt.Match(Threat{Evidence: map[string]string{"k": "101"}}) {
			t.Error("101 should NOT be < 100")
		}
	})
}

// TestMatchType exercises the matchType helper directly (bypassing the
// Enabled/Severity/Conditions plumbing in ThreatPolicy.Match) to pin down
// its exact prefix/suffix/match-all/literal-fallback semantics.
func TestMatchType(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		actual  string
		want    bool
	}{
		{"exact match", "impossible_travel", "impossible_travel", true},
		{"exact mismatch", "impossible_travel", "velocity_burst", false},
		{"exact match against empty actual", "impossible_travel", "", false},
		{"prefix match with operator-supplied boundary", "impossible_travel/*", "impossible_travel/critical", true},
		{"prefix match rejects run-on without the boundary", "impossible_travel/*", "impossible_travelXYZ", false},
		{"prefix match against the bare boundary itself", "impossible_travel/*", "impossible_travel/", true},
		{"prefix pattern with no boundary char matches run-on", "impossible_travel*", "impossible_travelXYZ", true},
		{"suffix match", "*_burst", "velocity_burst", true},
		{"suffix mismatch: actual too short", "*_burst", "burst", false},
		{"suffix mismatch: no boundary underscore", "*_burst", "xburst", false},
		{"bare star matches anything", "*", "anything", true},
		{"bare star matches empty actual", "*", "", true},
		{"mid-string asterisk is a literal, no match", "foo*bar", "foobar", false},
		{"mid-string asterisk is a literal, self-match", "foo*bar", "foo*bar", true},
		{"multiple asterisks is a literal, no match", "*foo*", "xfoox", false},
		{"multiple asterisks is a literal, self-match", "*foo*", "*foo*", true},
		{"double asterisk alone is a literal, no match", "**", "anything", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchType(tt.pattern, tt.actual)
			if got != tt.want {
				t.Errorf("matchType(%q, %q) = %v, want %v", tt.pattern, tt.actual, got, tt.want)
			}
		})
	}
}

// TestThreatConditions_GeoEvidenceContract pins the Decision-7 policy levers
// for geo findings: `geos` is an exists/eq-matchable key and `count` is the
// numeric cardinality gate. A count-conditioned policy on a threat WITHOUT
// the key fails closed (no match) — the documented behavior that keeps a
// policy scoped to geo findings from accidentally acting on rate_spike
// threats whose Evidence carries no count.
func TestThreatConditions_GeoEvidenceContract(t *testing.T) {
	t.Parallel()
	geoThreat := Threat{Type: ThreatVelocity, Severity: SeverityCritical,
		Evidence: map[string]string{"geos": "CN,US", "count": "2"}}

	t.Run("geos exists matches only when the geo set is present", func(t *testing.T) {
		tc := ThreatConditions{Key: "geos", Operator: "exists"}
		if !tc.Match(geoThreat) {
			t.Error("geos exists must match a geo finding")
		}
		if tc.Match(Threat{Type: ThreatRateSpike, Evidence: map[string]string{"token_thumbprint": "t"}}) {
			t.Error("geos exists must fail closed on a threat without the key")
		}
	})

	t.Run("geos eq matches the canonical sorted comma-join", func(t *testing.T) {
		tc := ThreatConditions{Key: "geos", Operator: "eq", Value: "CN,US"}
		if !tc.Match(geoThreat) {
			t.Error("geos eq must match the canonical sorted join")
		}
		tc.Value = "US,CN"
		if tc.Match(geoThreat) {
			t.Error("geos eq must reject a different ordering (the join is canonical)")
		}
	})

	t.Run("count gt is numeric and fails closed on a missing key", func(t *testing.T) {
		tc := ThreatConditions{Key: "count", Operator: "gt", Value: "1"}
		if !tc.Match(geoThreat) {
			t.Error("count gt 1 must match a 2-sighting finding")
		}
		tc.Value = "2"
		if tc.Match(geoThreat) {
			t.Error("count gt 2 must not match exactly 2")
		}
		// rate_spike carries no count key: fail closed, never match.
		if tc.Match(Threat{Type: ThreatRateSpike, Evidence: map[string]string{}}) {
			t.Error("count gt on a keyless threat must fail closed")
		}
	})
}
