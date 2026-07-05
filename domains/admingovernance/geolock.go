package admingovernance

import (
	"fmt"
	"net"
	"strings"

	"github.com/snaplink/sso/platform/geo"
)

// IPAllowlistConfig is the evaluated (pre-parsed) form of an operator's
// admin IP-allowlist / geo-lock configuration: CIDRs parsed to *net.IPNet,
// country codes upper-cased for exact match.
type IPAllowlistConfig struct {
	Nets      []*net.IPNet
	Countries map[string]bool
}

// ParseIPAllowlistConfig parses raw CIDR strings and country codes into an
// IPAllowlistConfig. Returns an error naming the first invalid CIDR (fail
// loud at config-load time rather than silently dropping a bad entry and
// under-restricting access).
func ParseIPAllowlistConfig(cidrs, countries []string) (IPAllowlistConfig, error) {
	cfg := IPAllowlistConfig{}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		_, ipnet, err := net.ParseCIDR(c)
		if err != nil {
			return IPAllowlistConfig{}, fmt.Errorf("admingovernance: invalid CIDR %q: %w", c, err)
		}
		cfg.Nets = append(cfg.Nets, ipnet)
	}
	for _, cc := range countries {
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if cc == "" {
			continue
		}
		if cfg.Countries == nil {
			cfg.Countries = make(map[string]bool, len(countries))
		}
		cfg.Countries[cc] = true
	}
	return cfg, nil
}

// Allowed reports whether ip (and, when a Countries allow-list is
// configured, the geo.GeoInfo the caller already resolved via the geo SPI)
// satisfies every configured dimension of cfg. Each dimension is OR-matched
// internally (any listed CIDR / any listed country) but ALL non-empty
// dimensions must pass (AND across dimensions): the intent of an allow-list
// is narrowing access, not widening it.
//
// Unlike the EXISTING geo enrichment middleware (fail-open — geo is a UX
// hint, see platform/geo's package doc), a configured Countries allow-list
// with NO resolved geo.GeoInfo FAILS CLOSED: an operator who explicitly
// opted into this governance gate must never have it silently no-op just
// because geo data happened to be unavailable for one request. A CIDR
// dimension needs no geo data at all — it is checked directly against ip.
func Allowed(ip net.IP, info *geo.GeoInfo, cfg IPAllowlistConfig) bool {
	if len(cfg.Nets) > 0 {
		if ip == nil || !anyContains(cfg.Nets, ip) {
			return false
		}
	}
	if len(cfg.Countries) > 0 {
		if info == nil || !cfg.Countries[strings.ToUpper(info.CountryCode)] {
			return false
		}
	}
	return true
}

func anyContains(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
