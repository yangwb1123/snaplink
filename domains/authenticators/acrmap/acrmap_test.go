package acrmap

import "testing"

func TestPatternACRMapper_EmptyUpstreamIsAlwaysEmpty(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Default: "should-never-be-returned-for-empty-input",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR(""); got != "" {
		t.Fatalf(`MapACR("") = %q, want "" (no claim, never the default)`, got)
	}
}

func TestPatternACRMapper_NoRuleMatchedNoDefaultIsEmptyNotError(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchExact, Pattern: "urn:known", MappedACR: "internal:known"},
		},
		// Default deliberately unset.
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR("urn:totally-unrecognized"); got != "" {
		t.Fatalf("MapACR(unmapped, no default) = %q, want \"\"", got)
	}
}

func TestPatternACRMapper_ExactMatch(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchExact, Pattern: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport", MappedACR: "urn:mace:incommon:iap:silver"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	got := m.MapACR("urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
	if got != "urn:mace:incommon:iap:silver" {
		t.Fatalf("exact match MapACR = %q, want urn:mace:incommon:iap:silver", got)
	}
}

func TestPatternACRMapper_RegexMatch(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchRegex, Pattern: `^https://schemas\.example\.com/acr/(gold|platinum)$`, MappedACR: "high"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR("https://schemas.example.com/acr/gold"); got != "high" {
		t.Fatalf("regex match MapACR = %q, want high", got)
	}
	if got := m.MapACR("https://schemas.example.com/acr/bronze"); got != "" {
		t.Fatalf("regex non-match MapACR = %q, want \"\" (no default configured)", got)
	}
}

func TestPatternACRMapper_PrefixMatch(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchPrefix, Pattern: "urn:mace:incommon:iap:", MappedACR: "incommon-assurance"},
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR("urn:mace:incommon:iap:bronze"); got != "incommon-assurance" {
		t.Fatalf("prefix match MapACR = %q, want incommon-assurance", got)
	}
}

func TestPatternACRMapper_DefaultFallback(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchExact, Pattern: "urn:known", MappedACR: "internal:known"},
		},
		Default: "internal:default-low",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR("urn:completely-unknown-upstream-value"); got != "internal:default-low" {
		t.Fatalf("default fallback MapACR = %q, want internal:default-low", got)
	}
}

// TestPatternACRMapper_PriorityOrderExactBeatsRegexBeatsPrefixBeatsDefault
// proves the cascade is a PRIORITY order (every exact rule, then every regex
// rule, then every prefix rule, then default) rather than declaration order:
// a single upstream value that could satisfy a prefix rule, a regex rule, AND
// an exact rule (all three deliberately declared with the prefix/regex rules
// listed FIRST in Config.Rules) must resolve via the exact rule.
func TestPatternACRMapper_PriorityOrderExactBeatsRegexBeatsPrefixBeatsDefault(t *testing.T) {
	t.Parallel()
	const upstream = "urn:mace:incommon:iap:silver"
	m, err := New(Config{
		Rules: []Rule{
			// Declared FIRST but lowest priority — a prefix match.
			{MatchType: MatchPrefix, Pattern: "urn:mace:incommon:iap:", MappedACR: "from-prefix"},
			// Declared SECOND but middle priority — a regex match.
			{MatchType: MatchRegex, Pattern: "^urn:mace:incommon:iap:silver$", MappedACR: "from-regex"},
			// Declared LAST but HIGHEST priority — an exact match. Must win
			// despite being declared after the other two.
			{MatchType: MatchExact, Pattern: upstream, MappedACR: "from-exact"},
		},
		Default: "from-default",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m.MapACR(upstream); got != "from-exact" {
		t.Fatalf("priority cascade broken: MapACR(%q) = %q, want from-exact (exact must beat regex/prefix/default regardless of declaration order)", upstream, got)
	}

	// Remove the exact rule (regenerate) to prove regex then beats prefix.
	m2, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchPrefix, Pattern: "urn:mace:incommon:iap:", MappedACR: "from-prefix"},
			{MatchType: MatchRegex, Pattern: "^urn:mace:incommon:iap:silver$", MappedACR: "from-regex"},
		},
		Default: "from-default",
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if got := m2.MapACR(upstream); got != "from-regex" {
		t.Fatalf("priority cascade broken: MapACR(%q) = %q, want from-regex (regex must beat prefix/default)", upstream, got)
	}
}

func TestPatternACRMapper_New_RejectsMalformedRegexAtLoadTimeNotPanic(t *testing.T) {
	t.Parallel()
	// An unbalanced group is an invalid regexp.Compile input — this MUST
	// surface as a returned error from New (config-load time), never a panic
	// discovered later when MapACR happens to be called with a matching
	// value.
	_, err := New(Config{
		Rules: []Rule{
			{MatchType: MatchRegex, Pattern: "(unterminated-group", MappedACR: "x"},
		},
	})
	if err == nil {
		t.Fatal("New must reject a malformed regex pattern, got nil error")
	}
}

func TestPatternACRMapper_New_RejectsUnknownMatchType(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		Rules: []Rule{
			{MatchType: "fuzzy", Pattern: "x", MappedACR: "y"},
		},
	})
	if err == nil {
		t.Fatal("New must reject an unknown match_type, got nil error")
	}
}

func TestPatternACRMapper_New_RejectsEmptyPatternOrMappedACR(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		rule Rule
	}{
		{"empty pattern", Rule{MatchType: MatchExact, Pattern: "", MappedACR: "x"}},
		{"empty mapped_acr", Rule{MatchType: MatchExact, Pattern: "x", MappedACR: ""}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(Config{Rules: []Rule{c.rule}})
			if err == nil {
				t.Fatalf("New must reject rule with %s, got nil error", c.name)
			}
		})
	}
}

func TestPatternACRMapper_EmptyConfigIsAlwaysEmpty(t *testing.T) {
	t.Parallel()
	m, err := New(Config{})
	if err != nil {
		t.Fatalf("New(zero Config): %v", err)
	}
	if got := m.MapACR("anything"); got != "" {
		t.Fatalf("zero Config MapACR = %q, want \"\"", got)
	}
}
