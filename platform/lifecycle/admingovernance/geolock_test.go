package admingovernance

import (
	"net"
	"testing"

	"github.com/yangwb1123/snaplink/platform/geo"
)

func TestParseIPAllowlistConfig(t *testing.T) {
	cfg, err := ParseIPAllowlistConfig([]string{"10.0.0.0/8", " 192.168.1.0/24 "}, []string{"us", " DE "})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(cfg.Nets) != 2 {
		t.Fatalf("Nets = %d; want 2", len(cfg.Nets))
	}
	if !cfg.Countries["US"] || !cfg.Countries["DE"] {
		t.Fatalf("Countries = %v; want US+DE upper-cased", cfg.Countries)
	}
}

func TestParseIPAllowlistConfig_InvalidCIDR(t *testing.T) {
	if _, err := ParseIPAllowlistConfig([]string{"not-a-cidr"}, nil); err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestAllowed_NoRulesConfigured(t *testing.T) {
	if !Allowed(net.ParseIP("1.2.3.4"), nil, IPAllowlistConfig{}) {
		t.Error("empty config must allow everything")
	}
}

func TestAllowed_CIDR(t *testing.T) {
	cfg, _ := ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, nil)
	if !Allowed(net.ParseIP("10.1.2.3"), nil, cfg) {
		t.Error("IP inside the allowed CIDR must pass")
	}
	if Allowed(net.ParseIP("8.8.8.8"), nil, cfg) {
		t.Error("IP outside the allowed CIDR must be denied")
	}
	if Allowed(nil, nil, cfg) {
		t.Error("nil IP with a CIDR rule configured must be denied")
	}
}

func TestAllowed_CountryFailsClosedWhenGeoMissing(t *testing.T) {
	cfg, _ := ParseIPAllowlistConfig(nil, []string{"US"})
	if Allowed(net.ParseIP("1.2.3.4"), nil, cfg) {
		t.Error("a configured country allow-list with NO resolved geo info must fail CLOSED")
	}
}

func TestAllowed_CountryMatch(t *testing.T) {
	cfg, _ := ParseIPAllowlistConfig(nil, []string{"US", "DE"})
	if !Allowed(net.ParseIP("1.2.3.4"), &geo.GeoInfo{CountryCode: "US"}, cfg) {
		t.Error("matching country must be allowed")
	}
	if Allowed(net.ParseIP("1.2.3.4"), &geo.GeoInfo{CountryCode: "CN"}, cfg) {
		t.Error("non-listed country must be denied")
	}
}

func TestAllowed_BothDimensionsMustPass(t *testing.T) {
	cfg, _ := ParseIPAllowlistConfig([]string{"10.0.0.0/8"}, []string{"US"})
	// IP matches CIDR but country doesn't -> denied (AND semantics).
	if Allowed(net.ParseIP("10.1.1.1"), &geo.GeoInfo{CountryCode: "CN"}, cfg) {
		t.Error("must require BOTH dimensions to pass when both are configured")
	}
	// Country matches but IP doesn't -> denied.
	if Allowed(net.ParseIP("8.8.8.8"), &geo.GeoInfo{CountryCode: "US"}, cfg) {
		t.Error("must require BOTH dimensions to pass when both are configured")
	}
	// Both match -> allowed.
	if !Allowed(net.ParseIP("10.1.1.1"), &geo.GeoInfo{CountryCode: "US"}, cfg) {
		t.Error("must allow when both configured dimensions pass")
	}
}
