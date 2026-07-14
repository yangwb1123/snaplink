package threataction

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"
)

// ThreatPolicy maps one threat class to an action. Evaluated by the
// executor BEFORE executing — if no policy matches, default is Noop.
//
// Carries both yaml + json tags: json for the admin CRUD API
// (domains/threataction/admin.go), yaml so config.ThreatActionConfig can seed
// the ThreatPolicyStore with a boot-time policy list (same dual-tag pattern as
// domains/conditionalaccess.Policy / domains/tokenpolicy.Policy).
type ThreatPolicy struct {
	Name    string `yaml:"name" json:"name"`
	Enabled bool   `yaml:"enabled" json:"enabled"`

	// Type selects which Threat.Type values this policy applies to, matched
	// via matchType. Empty matches any type (unchanged "any" shorthand).
	// Otherwise:
	//   - no "*" anywhere            → exact match: "impossible_travel"
	//   - a single trailing "*"      → prefix match: "impossible_travel/*"
	//   - a single leading "*"       → suffix match: "*_burst"
	//   - the bare "*"               → matches any type, same result as
	//     leaving Type empty. Kept as an explicit, self-documenting choice
	//     for policy authors who want "match everything" to be visible in
	//     the policy itself rather than inferred from an absent field.
	// Any other placement of "*" (mid-string, or more than one) is NOT
	// glob-expanded — see matchType's doc comment for why.
	Type     string `yaml:"type" json:"type"`
	Severity string `yaml:"severity" json:"severity"` // empty = any; "critical", "warn", "warn+critical"
	Action   Action `yaml:"action" json:"action"`

	// RateLimit caps how often this action fires per (subject, type) per window.
	// Prevents notification storms on a flapping detection.
	RateLimit *RateLimitPolicy `yaml:"rate_limit,omitempty" json:"rate_limit,omitempty"`

	// Conditions is an optional expression over Threat.Evidence.
	Conditions ThreatConditions `yaml:"conditions,omitempty" json:"conditions,omitempty"`
}

// RateLimitPolicy caps how often an action fires per (subject, type) per window.
type RateLimitPolicy struct {
	PerWindow Duration `yaml:"per_window" json:"per_window"`
	Max       int      `yaml:"max" json:"max"`
}

// Duration is a JSON-compatible time.Duration wrapper.
type Duration struct {
	time.Duration
}

// MarshalJSON implements json.Marshaler.
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

// UnmarshalJSON implements json.Unmarshaler.
func (d *Duration) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// MarshalYAML implements goccy/go-yaml's BytesMarshaler so config.
// ThreatActionConfig's inline Policies list renders the same "1h"-style
// duration string as the JSON admin API.
func (d Duration) MarshalYAML() ([]byte, error) {
	return []byte(d.String()), nil
}

// UnmarshalYAML implements goccy/go-yaml's BytesUnmarshaler (mirrors
// UnmarshalJSON) so a config `per_window: 1h` parses without a custom loader.
func (d *Duration) UnmarshalYAML(b []byte) error {
	v, err := time.ParseDuration(strings.TrimSpace(string(b)))
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// ThreatConditions is an optional expression over Threat.Evidence.
type ThreatConditions struct {
	// KeySelector is an Evidence key; operator means "value must match".
	// Empty = unconditional.
	Key      string `yaml:"key,omitempty" json:"key,omitempty"`
	Operator string `yaml:"operator,omitempty" json:"operator,omitempty"` // "eq", "gt", "lt", "exists"
	Value    string `yaml:"value,omitempty" json:"value,omitempty"`
}

// Match evaluates whether the conditions hold for the given threat.
func (tc ThreatConditions) Match(threat Threat) bool {
	if tc.Key == "" {
		return true // unconditional
	}
	val, exists := threat.Evidence[tc.Key]
	switch tc.Operator {
	case "exists":
		return exists
	case "eq":
		return exists && val == tc.Value
	case "gt":
		if !exists {
			return false
		}
		v1, err1 := strconv.ParseFloat(val, 64)
		v2, err2 := strconv.ParseFloat(tc.Value, 64)
		if err1 != nil || err2 != nil {
			return val > tc.Value // fallback to string comparison
		}
		return v1 > v2
	case "lt":
		if !exists {
			return false
		}
		v1, err1 := strconv.ParseFloat(val, 64)
		v2, err2 := strconv.ParseFloat(tc.Value, 64)
		if err1 != nil || err2 != nil {
			return val < tc.Value // fallback to string comparison
		}
		return v1 < v2
	default:
		return exists // unknown operator → existence check only
	}
}

// MatchesSeverity reports whether the policy's severity filter matches
// the threat's severity. Empty policy severity matches any severity.
func (tp ThreatPolicy) MatchesSeverity(threatSeverity string) bool {
	if tp.Severity == "" {
		return true
	}
	// Support "warn+critical" syntax.
	parts := strings.Split(tp.Severity, "+")
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == threatSeverity {
			return true
		}
	}
	return false
}

// Match reports whether this policy applies to the given threat.
func (tp ThreatPolicy) Match(threat Threat) bool {
	if !tp.Enabled {
		return false
	}
	if tp.Type != "" && !matchType(tp.Type, threat.Type) {
		return false
	}
	if !tp.MatchesSeverity(threat.Severity) {
		return false
	}
	if !tp.Conditions.Match(threat) {
		return false
	}
	return true
}

// matchType reports whether actual satisfies pattern, supporting exactly
// three wildcard forms beyond a literal exact match — prefix, suffix, and
// match-all — deliberately NOT a full glob/regex engine:
//
//   - pattern == actual              → exact match (today's only behavior,
//     unchanged for any pattern containing no "*")
//   - pattern == "*"                 → matches any actual
//   - pattern == "prefix*"           → actual must start with "prefix"
//     (plain string prefix — no implicit word-boundary is inserted; if the
//     operator wants one, they write it into the pattern themselves, e.g.
//     "impossible_travel/*" requires the literal "/" and so will NOT match
//     "impossible_travelXYZ", whereas "impossible_travel*" — no slash — WILL)
//   - pattern == "*suffix"           → actual must end with "suffix"
//
// Any other placement of "*" — in the middle ("foo*bar"), or more than one
// asterisk ("*foo*", "**") — is treated as a LITERAL string (asterisk
// character included) and compared for exact equality, NOT expanded into a
// glob. This is a deliberate, conservative fallback rather than an error:
// ThreatPolicy is writable both from YAML config (config.ThreatActionConfig)
// and the admin CRUD API (HandleAdminPutPolicy in admin.go), and NEITHER
// path validates Type before it reaches Match — there is no "validate on
// save" hook today. A malformed pattern therefore must degrade safely here,
// at evaluation time, rather than assume validation happened upstream. A
// literal-string fallback can only match the operator's exact (unlikely)
// input and never matches MORE broadly than a plain typo would already have
// meant under pre-wildcard exact-match semantics, so a malformed pattern
// fails closed (matches nothing in practice) instead of accidentally
// granting a policy broader reach than the operator wrote.
func matchType(pattern, actual string) bool {
	switch strings.Count(pattern, "*") {
	case 0:
		return pattern == actual
	case 1:
		if strings.HasPrefix(pattern, "*") {
			return strings.HasSuffix(actual, pattern[1:])
		}
		if strings.HasSuffix(pattern, "*") {
			return strings.HasPrefix(actual, pattern[:len(pattern)-1])
		}
	}
	// Malformed: "*" in the middle, or more than one "*". Literal fallback.
	return pattern == actual
}

// ErrPolicyNotFound is returned when a named policy doesn't exist.
var ErrPolicyNotFound = errors.New("threataction: policy not found")

// ThreatPolicyStore persists policies. Admin API CRUD.
type ThreatPolicyStore interface {
	List(ctx context.Context) ([]ThreatPolicy, error)
	Get(ctx context.Context, name string) (*ThreatPolicy, error)
	Put(ctx context.Context, policy ThreatPolicy) error
	Delete(ctx context.Context, name string) error
}
