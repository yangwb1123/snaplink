// Package acrmap is the reference authenticators.ACRMapper implementation: a
// configurable exact -> regex -> prefix -> default cascade that normalizes a
// federated IdP's raw authentication-context signal (an OIDC `acr` claim
// today; a SAML AuthnContextClassRef URI once infrastructure/saml exposes one)
// onto this SDK's own acr vocabulary — see authenticators.ACRMapper's doc for
// why this mapping exists and what consumes its output.
//
// This package has NO dependency on domains/authenticators: MapACR's signature
// (string) string is all authenticators.WithACRMapper needs, so
// *PatternACRMapper satisfies authenticators.ACRMapper structurally (Go
// interfaces). That keeps the cascade a small, dependency-free leaf usable
// from any future consumer — a SAML SP ACR mapper, a WebAuthn/LDAP strength
// normalizer — without importing domains/authenticators.
package acrmap

import (
	"fmt"
	"regexp"
	"strings"
)

// MatchType selects how a Rule's Pattern is compared against the upstream ACR.
type MatchType string

const (
	// MatchExact requires the upstream ACR to equal Pattern byte-for-byte.
	MatchExact MatchType = "exact"
	// MatchRegex requires Pattern (a Go regexp) to match somewhere in the
	// upstream ACR (regexp.MatchString semantics — anchor with ^...$ for a
	// full-string match).
	MatchRegex MatchType = "regex"
	// MatchPrefix requires the upstream ACR to start with Pattern.
	MatchPrefix MatchType = "prefix"
)

// Rule maps one upstream ACR pattern onto this SDK's internal ACR value.
type Rule struct {
	MatchType MatchType `yaml:"match_type" json:"match_type"`
	Pattern   string    `yaml:"pattern" json:"pattern"`
	MappedACR string    `yaml:"mapped_acr" json:"mapped_acr"`
}

// Config is the operator-declared rule set + default fallback that New
// compiles into a live PatternACRMapper.
type Config struct {
	// Rules are evaluated in PRIORITY order — every exact rule, then every
	// regex rule, then every prefix rule — REGARDLESS of the order they are
	// declared in this slice. Within one match-type phase, the first
	// declared rule that matches wins.
	Rules []Rule `yaml:"rules,omitempty" json:"rules,omitempty"`
	// Default is returned when no rule matches (or Rules is empty). ""
	// (the zero value) means "no claim" — MapACR returns "" and
	// AuthResult.AchievedACR stays unset.
	Default string `yaml:"default,omitempty" json:"default,omitempty"`
}

// compiledRule is a Rule with its regexp pre-compiled (MatchRegex only) so
// MapACR never compiles a pattern on the request path.
type compiledRule struct {
	pattern   string
	re        *regexp.Regexp
	mappedACR string
}

// PatternACRMapper is the reference authenticators.ACRMapper: a
// priority-cascaded (exact -> regex -> prefix -> default) rule matcher.
// Immutable after New returns — safe for concurrent MapACR calls.
type PatternACRMapper struct {
	exact    []compiledRule
	regex    []compiledRule
	prefix   []compiledRule
	fallback string
}

// New validates cfg and compiles every regex rule EAGERLY, so a malformed
// pattern fails LOUDLY at config-load time — never a panic (or a silently
// dead rule) discovered on the first request that happens to hit it.
func New(cfg Config) (*PatternACRMapper, error) {
	m := &PatternACRMapper{fallback: cfg.Default}
	for i, r := range cfg.Rules {
		if err := m.addRule(i, r); err != nil {
			return nil, err
		}
	}
	return m, nil
}

// addRule validates + compiles one rule and appends it to the matching
// per-match-type bucket. Split out of New to keep both functions well under
// the function-length/complexity budget.
func (m *PatternACRMapper) addRule(i int, r Rule) error {
	if r.Pattern == "" {
		return fmt.Errorf("acrmap: rule %d: pattern required", i)
	}
	if r.MappedACR == "" {
		return fmt.Errorf("acrmap: rule %d: mapped_acr required", i)
	}
	cr := compiledRule{pattern: r.Pattern, mappedACR: r.MappedACR}
	switch r.MatchType {
	case MatchExact:
		m.exact = append(m.exact, cr)
	case MatchRegex:
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return fmt.Errorf("acrmap: rule %d: invalid regex %q: %w", i, r.Pattern, err)
		}
		cr.re = re
		m.regex = append(m.regex, cr)
	case MatchPrefix:
		m.prefix = append(m.prefix, cr)
	default:
		return fmt.Errorf("acrmap: rule %d: unknown match_type %q (want %q, %q, or %q)",
			i, r.MatchType, MatchExact, MatchRegex, MatchPrefix)
	}
	return nil
}

// MapACR implements authenticators.ACRMapper: "" in (no claim reported) or no
// rule matched -> "" out, NEVER an error — exact, then regex, then prefix,
// then the configured default, in that PRIORITY ORDER regardless of the
// rules' declaration order in Config.Rules (a value matched by both an exact
// rule and an earlier-declared prefix rule always resolves via the exact
// rule).
func (m *PatternACRMapper) MapACR(upstreamACR string) string {
	if upstreamACR == "" {
		return ""
	}
	for _, r := range m.exact {
		if r.pattern == upstreamACR {
			return r.mappedACR
		}
	}
	for _, r := range m.regex {
		if r.re.MatchString(upstreamACR) {
			return r.mappedACR
		}
	}
	for _, r := range m.prefix {
		if strings.HasPrefix(upstreamACR, r.pattern) {
			return r.mappedACR
		}
	}
	return m.fallback
}
