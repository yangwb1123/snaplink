package defaultimpl

import "github.com/snaplink/sso/spi"

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
)

// RuleBasedRiskScorer is the reference rule-based [spi.RiskScorer].
// It is intentionally simple — the 80% case of an operator who wants
// declarative deny-by-IP / deny-by-country / allow-only-from-these
// without writing Go. Anything more involved (impossible-travel,
// device-fingerprint deltas, ML scoring) should plug in a custom
// RiskScorer directly via [sso.WithRiskScorer].
//
// Evaluation order (first match wins; later rules are short-circuited):
//
//  1. IP in IPDenyList                              → Deny
//  2. IPAllowList non-empty AND IP not in allow set → Deny
//  3. Country in CountryDenyList                    → Deny
//  4. CountryAllowList non-empty AND country not in allow set → Deny
//     (when DenyOnGeoMissing is false, a missing Geo field skips this
//     rule rather than denying — the safer default for deployments
//     where geo enrichment is best-effort)
//  5. → Allow
//
// IP rules accept individual IPs ("203.0.113.7") and CIDR ranges
// ("203.0.113.0/24"). Country comparisons are case-insensitive (the
// allow/deny sets normalize to upper case so ISO 3166-1 alpha-2
// codes match whether the geo provider emits "US" or "us").
type RuleBasedRiskScorer struct {
	denyNets         []*net.IPNet
	denyIPs          map[string]struct{}
	allowNets        []*net.IPNet
	allowIPs         map[string]struct{}
	hasAllowIPRules  bool
	denyCountries    map[string]struct{}
	allowCountries   map[string]struct{}
	hasAllowCountry  bool
	denyOnGeoMissing bool
}

// RuleBasedRiskScorerConfig is the construction-time input. Callers
// pass a literal struct rather than fluent options because there's
// only a handful of fields and they're all data, not behavior.
//
// IPDenyList + IPAllowList accept CIDR ("10.0.0.0/8") or single-IP
// ("203.0.113.7") strings — the same set syntax operators write in
// netpolicy YAML. CountryDenyList + CountryAllowList are
// ISO 3166-1 alpha-2 (e.g. "US", "DE"). DenyOnGeoMissing controls
// whether the CountryAllowList rule fires when the geo lookup
// returned nothing — false (the default) treats geo as best-effort
// and lets the login through; true treats geo as a hard requirement.
type RuleBasedRiskScorerConfig struct {
	IPDenyList       []string
	IPAllowList      []string
	CountryDenyList  []string
	CountryAllowList []string
	DenyOnGeoMissing bool
}

// NewRuleBasedRiskScorer parses the supplied config into the
// pre-resolved sets the hot path consults. Returns an error on
// malformed CIDR / IP entries so misconfigurations fail at boot
// rather than at the first request.
func NewRuleBasedRiskScorer(cfg RuleBasedRiskScorerConfig) (*RuleBasedRiskScorer, error) {
	s := &RuleBasedRiskScorer{
		denyIPs:          make(map[string]struct{}),
		allowIPs:         make(map[string]struct{}),
		denyCountries:    make(map[string]struct{}),
		allowCountries:   make(map[string]struct{}),
		denyOnGeoMissing: cfg.DenyOnGeoMissing,
	}
	for _, raw := range cfg.IPDenyList {
		if err := parseIPOrCIDR(raw, &s.denyNets, s.denyIPs); err != nil {
			return nil, fmt.Errorf("risk: ip_deny_list %q: %w", raw, err)
		}
	}
	for _, raw := range cfg.IPAllowList {
		if err := parseIPOrCIDR(raw, &s.allowNets, s.allowIPs); err != nil {
			return nil, fmt.Errorf("risk: ip_allow_list %q: %w", raw, err)
		}
		s.hasAllowIPRules = true
	}
	for _, raw := range cfg.CountryDenyList {
		if c := strings.ToUpper(strings.TrimSpace(raw)); c != "" {
			s.denyCountries[c] = struct{}{}
		}
	}
	for _, raw := range cfg.CountryAllowList {
		if c := strings.ToUpper(strings.TrimSpace(raw)); c != "" {
			s.allowCountries[c] = struct{}{}
			s.hasAllowCountry = true
		}
	}
	return s, nil
}

// Score implements [spi.RiskScorer].
func (s *RuleBasedRiskScorer) Score(_ context.Context, req *spi.RiskRequest) (*spi.RiskAssessment, error) {
	if req == nil {
		return &spi.RiskAssessment{Decision: spi.DecisionAllow}, nil
	}
	if d := s.scoreIP(parseRequestIP(req.RemoteIP)); d != nil {
		return d, nil
	}
	if d := s.scoreCountry(geoCountry(req)); d != nil {
		return d, nil
	}
	return &spi.RiskAssessment{Decision: spi.DecisionAllow}, nil
}

// scoreIP applies the IP deny/allow rules (steps 1-2). Returns a Deny
// assessment when the IP is blocked, or nil to fall through to country
// rules — including when ip is nil (no usable IP skips IP rules entirely)
// or when an allow-listed IP matches (the original goto countryRules).
func (s *RuleBasedRiskScorer) scoreIP(ip net.IP) *spi.RiskAssessment {
	if ip == nil {
		return nil
	}
	if _, denied := s.denyIPs[ip.String()]; denied {
		return deny("ip_deny_list", "ip-deny")
	}
	for _, n := range s.denyNets {
		if n.Contains(ip) {
			return deny("ip_deny_list", "ip-deny")
		}
	}
	if !s.hasAllowIPRules {
		return nil
	}
	if _, ok := s.allowIPs[ip.String()]; ok {
		return nil
	}
	for _, n := range s.allowNets {
		if n.Contains(ip) {
			return nil
		}
	}
	return deny("ip_allow_list", "ip-not-allowed")
}

// scoreCountry applies the country deny/allow rules (steps 3-4) to the
// already-normalized country code. Returns a Deny assessment or nil to
// fall through to Allow. Preserves the DenyOnGeoMissing semantics: an
// empty country only denies when an allow list exists AND geo is required.
func (s *RuleBasedRiskScorer) scoreCountry(country string) *spi.RiskAssessment {
	if country != "" {
		if _, denied := s.denyCountries[country]; denied {
			return deny("country_deny_list", "country-deny")
		}
	}
	if !s.hasAllowCountry {
		return nil
	}
	switch {
	case country != "":
		if _, ok := s.allowCountries[country]; !ok {
			return deny("country_allow_list", "country-not-allowed")
		}
	case s.denyOnGeoMissing:
		return deny("country_allow_list", "geo-missing")
	}
	return nil
}

var _ spi.RiskScorer = (*RuleBasedRiskScorer)(nil)

func parseIPOrCIDR(raw string, nets *[]*net.IPNet, set map[string]struct{}) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errors.New("empty entry")
	}
	if strings.Contains(raw, "/") {
		_, n, err := net.ParseCIDR(raw)
		if err != nil {
			return err
		}
		*nets = append(*nets, n)
		return nil
	}
	ip := net.ParseIP(raw)
	if ip == nil {
		return errors.New("not an IP or CIDR")
	}
	set[ip.String()] = struct{}{}
	return nil
}

// parseRequestIP normalizes whatever the RiskRequest.RemoteIP field
// carries (raw IP, IP:port, or empty). Returns nil when no usable
// IP — the caller then skips IP-based rules entirely.
func parseRequestIP(raw string) net.IP {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if host, _, err := net.SplitHostPort(raw); err == nil {
		raw = host
	}
	return net.ParseIP(raw)
}

func geoCountry(req *spi.RiskRequest) string {
	if req.Geo == nil {
		return ""
	}
	return strings.ToUpper(strings.TrimSpace(req.Geo.CountryCode))
}

func deny(tag, reason string) *spi.RiskAssessment {
	return &spi.RiskAssessment{
		Decision: spi.DecisionDeny,
		Reason:   reason,
		Tags:     []string{tag},
	}
}
