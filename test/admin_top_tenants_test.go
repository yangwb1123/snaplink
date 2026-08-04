package ssotest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	meteringmemory "github.com/yangwb1123/snaplink/domains/metering/memory"
	"github.com/yangwb1123/snaplink/interfaces/sso"
)

// topTenantsServer builds a server whose memory aggregator is pre-seeded with
// three tenants on 2026-07-01 (day period): high=500, mid=50, low=5 logins.
func topTenantsServer(t *testing.T) *httptest.Server {
	t.Helper()
	agg := meteringmemory.NewAggregator()
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	agg.Record(&metering.TenantUsage{TenantID: "low", Period: metering.PeriodDay, PeriodStart: start, Logins: 5})
	agg.Record(&metering.TenantUsage{TenantID: "high", Period: metering.PeriodDay, PeriodStart: start, Logins: 500, TokensIssued: 900})
	agg.Record(&metering.TenantUsage{TenantID: "mid", Period: metering.PeriodDay, PeriodStart: start, Logins: 50})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithTenantUsageAggregator(agg),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

func TestTopTenantsRoute_RanksByLoginsAndHonorsLimit(t *testing.T) {
	hs := topTenantsServer(t)

	resp, err := http.Get(hs.URL + "/api/v1/admin/usage/top-tenants?period=day&start=2026-07-01&limit=2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var out struct {
		Status  string                  `json:"status"`
		Tenants []*metering.TenantUsage `json:"tenants"`
		Total   int                     `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != "ok" || out.Total != 2 || len(out.Tenants) != 2 {
		t.Fatalf("envelope = %+v, want status=ok total=2 len=2", out)
	}
	if out.Tenants[0].TenantID != "high" || out.Tenants[1].TenantID != "mid" {
		t.Errorf("ranking = [%s %s], want [high mid]", out.Tenants[0].TenantID, out.Tenants[1].TenantID)
	}
	if out.Tenants[0].Logins != 500 {
		t.Errorf("Logins = %d, want 500", out.Tenants[0].Logins)
	}
}

func TestTopTenantsRoute_BadInputs(t *testing.T) {
	hs := topTenantsServer(t)
	for _, q := range []string{"?period=week", "?limit=abc", "?limit=-1", "?start=notadate"} {
		resp, err := http.Get(hs.URL + "/api/v1/admin/usage/top-tenants" + q)
		if err != nil {
			t.Fatalf("GET %s: %v", q, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", q, resp.StatusCode)
		}
	}
}

// Group-prefix regression guard, same as TestTenantUsageRoute_ResolvesAtDocumentedPath.
func TestTopTenantsRoute_DoubledPrefixDoesNotResolve(t *testing.T) {
	hs := topTenantsServer(t)
	resp, err := http.Get(hs.URL + "/api/v1/api/v1/admin/usage/top-tenants")
	if err != nil {
		t.Fatalf("GET doubled: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("doubled path resolved (status %d), want 404", resp.StatusCode)
	}
}
