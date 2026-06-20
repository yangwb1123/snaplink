package audit_test

import (
	"net/http/httptest"
	"testing"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/geo"
	"github.com/snaplink/sso/shared/core"
)

func TestSetMeta_LazyAllocAndSkipEmpty(t *testing.T) {
	e := &audit.Event{}
	audit.SetMeta(e, "k0", "") // empty value: skipped, no alloc
	if e.Metadata != nil {
		t.Fatalf("empty value must not allocate map, got %v", e.Metadata)
	}
	audit.SetMeta(e, "k1", "v1")
	if e.Metadata["k1"] != "v1" {
		t.Fatalf("k1 = %q", e.Metadata["k1"])
	}
}

// SetMeta must never clobber prior enrichment — the central invariant the
// whole audit metadata contract rests on (AGENTS.md §4).
func TestSetMeta_NeverClobbersExistingKeys(t *testing.T) {
	e := &audit.Event{}
	audit.SetMeta(e, "geo.country_code", "US")
	audit.SetMeta(e, "tenant.id", "t-1")
	// A later handler adding its own key must leave the enrichment intact.
	audit.SetMeta(e, "rotation", "true")
	if e.Metadata["geo.country_code"] != "US" {
		t.Fatalf("geo key clobbered: %v", e.Metadata)
	}
	if e.Metadata["tenant.id"] != "t-1" {
		t.Fatalf("tenant key clobbered: %v", e.Metadata)
	}
	if e.Metadata["rotation"] != "true" {
		t.Fatalf("new key missing: %v", e.Metadata)
	}
}

func TestClientIP_Precedence(t *testing.T) {
	tests := []struct {
		name      string
		xff, xrip string
		remote    string
		want      string
	}{
		{"xff-single", "198.51.100.4", "", "10.0.0.1:80", "198.51.100.4"},
		{"xff-first-of-list", "198.51.100.4, 10.0.0.9", "", "10.0.0.1:80", "198.51.100.4"},
		{"xff-padded", "  198.51.100.5  ", "", "10.0.0.1:80", "198.51.100.5"},
		{"x-real-ip", "", "203.0.113.9", "10.0.0.1:80", "203.0.113.9"},
		{"remote-addr-port-stripped", "", "", "192.0.2.7:54321", "192.0.2.7"},
		{"remote-addr-no-port", "", "", "192.0.2.8", "192.0.2.8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			if tc.xff != "" {
				r.Header.Set("X-Forwarded-For", tc.xff)
			}
			if tc.xrip != "" {
				r.Header.Set("X-Real-IP", tc.xrip)
			}
			if got := audit.ClientIP(r); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEventFromRequest_TracingHeaders(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set(core.HeaderRequestID, "req-123")
	r.Header.Set(core.HeaderParentSpanID, "parent-span")
	r.Header.Set("User-Agent", "ua")
	r.Header.Set(core.HeaderTraceparent, "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01")
	ctx := core.NewContext(httptest.NewRecorder(), r)

	e := audit.EventFromRequest(ctx)
	if e.RequestID != "req-123" {
		t.Fatalf("request id = %q", e.RequestID)
	}
	if e.ParentSpanID != "parent-span" {
		t.Fatalf("parent span = %q", e.ParentSpanID)
	}
	if e.UserAgent != "ua" {
		t.Fatalf("ua = %q", e.UserAgent)
	}
	if e.TraceID != "0af7651916cd43dd8448eb211c80319c" || e.SpanID != "b7ad6b7169203331" {
		t.Fatalf("traceparent not parsed: trace=%q span=%q", e.TraceID, e.SpanID)
	}
}

func TestEventFromRequest_MalformedTraceparentIgnored(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	r.Header.Set(core.HeaderTraceparent, "not-a-valid-traceparent")
	ctx := core.NewContext(httptest.NewRecorder(), r)
	e := audit.EventFromRequest(ctx)
	if e.TraceID != "" || e.SpanID != "" {
		t.Fatalf("malformed traceparent should leave ids empty: trace=%q span=%q", e.TraceID, e.SpanID)
	}
}

func TestEventFromRequest_NoMiddlewareLeavesFieldsEmpty(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	e := audit.EventFromRequest(ctx)
	if e.TenantID != "" || e.TraceID != "" || len(e.Metadata) != 0 {
		t.Fatalf("expected empty enrichment without middleware, got %+v", e)
	}
}

func TestEnrichTenant_LiftsResolvedTenant(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	ctx.Set(tenant.HandlerContextKey, &tenant.Resolved{
		Tenant: &tenant.Tenant{ID: "t-9", Slug: "acme"},
		Domain: &tenant.Domain{Hostname: "acme.example.com"},
	})

	e := audit.EventFromRequest(ctx)
	if e.TenantID != "t-9" {
		t.Fatalf("TenantID = %q", e.TenantID)
	}
	if e.Metadata["tenant.id"] != "t-9" || e.Metadata["tenant.slug"] != "acme" {
		t.Fatalf("tenant meta: %v", e.Metadata)
	}
	if e.Metadata["tenant.domain"] != "acme.example.com" {
		t.Fatalf("tenant.domain = %q", e.Metadata["tenant.domain"])
	}
}

func TestEnrichTenant_NilResolvedNoOp(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	// Resolved present but Tenant nil — the no-op branch.
	ctx.Set(tenant.HandlerContextKey, &tenant.Resolved{})
	e := audit.EventFromRequest(ctx)
	if e.TenantID != "" || len(e.Metadata) != 0 {
		t.Fatalf("nil tenant should add nothing, got %+v", e)
	}
}

func TestEnrichGeo_LiftsGeoInfo(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	ctx.Set(geo.HandlerContextKey, &geo.GeoInfo{
		CountryCode:         "US",
		Region:              "US-CA",
		City:                "SF",
		RecommendedLanguage: "en-US",
	})

	e := audit.EventFromRequest(ctx)
	if e.Metadata["geo.country_code"] != "US" || e.Metadata["geo.region"] != "US-CA" {
		t.Fatalf("geo meta: %v", e.Metadata)
	}
	if e.Metadata["geo.city"] != "SF" || e.Metadata["geo.recommended_language"] != "en-US" {
		t.Fatalf("geo city/lang: %v", e.Metadata)
	}
}

func TestEnrichRegion_LiftsServingRegion(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	ctx.Set(region.HandlerContextKey, region.ID("eu-west"))

	e := audit.EventFromRequest(ctx)
	if e.Metadata["region.serving"] != "eu-west" {
		t.Fatalf("region.serving = %q", e.Metadata["region.serving"])
	}
}

func TestEnrichRegion_EmptyIDAddsNoKey(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	// Middleware ran but resolved no region (unconstrained request).
	ctx.Set(region.HandlerContextKey, region.ID(""))
	e := audit.EventFromRequest(ctx)
	if _, ok := e.Metadata["region.serving"]; ok {
		t.Fatalf("empty region ID should add no key, got %v", e.Metadata)
	}
}

// All three enrichers stacking onto one event must coexist — SetMeta's
// no-clobber guarantee proven end-to-end through EventFromRequest.
func TestEventFromRequest_AllEnrichersCoexist(t *testing.T) {
	r := httptest.NewRequest("POST", "/token", nil)
	ctx := core.NewContext(httptest.NewRecorder(), r)
	ctx.Set(tenant.HandlerContextKey, &tenant.Resolved{Tenant: &tenant.Tenant{ID: "t", Slug: "s"}})
	ctx.Set(geo.HandlerContextKey, &geo.GeoInfo{CountryCode: "DE"})
	ctx.Set(region.HandlerContextKey, region.ID("eu-central"))

	e := audit.EventFromRequest(ctx)
	if e.Metadata["tenant.id"] != "t" || e.Metadata["geo.country_code"] != "DE" || e.Metadata["region.serving"] != "eu-central" {
		t.Fatalf("enrichers stomped each other: %v", e.Metadata)
	}
}
