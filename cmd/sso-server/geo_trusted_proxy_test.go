package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/platform/audit"
)

// TestWireGeoRegionRisk_TrustedProxiesGatesGeoIPExtraction proves that once
// security.trusted_proxies is configured, geo enrichment (and therefore any
// downstream spi.RiskScorer country rule — see config.RiskConfig's
// CountryDenyList/CountryAllowList) resolves the country from the
// TrustedProxies-validated real client IP, NOT the raw, attacker-settable
// leftmost X-Forwarded-For hop.
//
// config/config_metrics_security.go's TrustedProxiesConfig doc comment
// promises the validated address feeds "rate-limiting AND geo enrichment",
// but before this fix cmd/sso-server never wired GeoMiddlewareOptions'
// IPExtractor: geo.DefaultIPExtractor always trusts the raw leftmost XFF
// entry directly. A request that legitimately traverses the ONE configured
// trusted-proxy tier can still have its resolved country hijacked by
// prepending an arbitrary forged hop to the left of the chain — letting an
// attacker evade a country_deny_list rule (or manufacture a false
// RequireMFA/Deny) regardless of the trusted_proxies allowlist.
func TestWireGeoRegionRisk_TrustedProxiesGatesGeoIPExtraction(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.ClientRegistration.Enabled = true
	cfg.ClientRegistration.AllowOpenRegistration = true
	cfg.Audit.Enabled = true
	cfg.Audit.MemoryCapacity = 8
	cfg.Geo.Enabled = true
	cfg.Geo.Backend = "static"
	cfg.Geo.Static.Entries = []config.GeoStaticEntry{
		{CIDR: "9.9.9.9/32", CountryCode: "XX"}, // attacker-forged leftmost hop
		{CIDR: "5.6.7.8/32", CountryCode: "US"}, // real client, as observed by the trusted proxy
	}
	cfg.Security.TrustedProxies.CIDRs = []string{"10.0.0.0/8"}
	cfg.Security.TrustedProxies.Hops = 1

	a, err := buildApp(cfg, quietLogger())
	if err != nil {
		t.Fatalf("buildApp: %v", err)
	}
	defer func() { _ = a.registry.Close() }()

	srv := httptest.NewServer(a.server.Handler())
	defer srv.Close()

	req, err := http.NewRequest(http.MethodPost, srv.URL+"/register",
		strings.NewReader(`{"redirect_uris":["https://app.example/cb"]}`))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// "9.9.9.9" is an attacker-forged leftmost hop; "5.6.7.8" is the address
	// the one trusted proxy tier (10.0.0.1, in the configured 10.0.0.0/8
	// CIDR) actually observed and appended. TrustedProxies with Hops=1
	// must peel 10.0.0.1 and land on 5.6.7.8 as the real client — the
	// forged 9.9.9.9 must never surface downstream (mirrors
	// interfaces/middleware.TestTrustedProxies_ForgedHeader).
	req.Header.Set("X-Forwarded-For", "9.9.9.9, 5.6.7.8, 10.0.0.1")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /register: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /register status = %d; want 201", resp.StatusCode)
	}

	sink, ok := a.recorder.Sink().(*audit.MemorySink)
	if !ok {
		t.Fatalf("sink type = %T; want *audit.MemorySink", a.recorder.Sink())
	}
	events, err := sink.Query(context.Background(), audit.Query{Type: audit.EventClientRegistered, Limit: 10})
	if err != nil {
		t.Fatalf("sink.Query: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("client_registered events = %d; want 1", len(events))
	}

	got := events[0].Metadata["geo.country_code"]
	if got != "US" {
		t.Errorf("geo.country_code = %q; want %q (the trusted-proxy-validated client IP's country) — "+
			"got the attacker-forged leftmost X-Forwarded-For hop's country instead, proving geo "+
			"enrichment ignores security.trusted_proxies", got, "US")
	}
}
