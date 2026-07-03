package tokenusage

import (
	"testing"
	"time"
)

// aggregatePortfolio is pure over the aggregated buckets, so it is tested
// in-package with synthetic buckets (no store needed).

func bkt(min time.Time, client string, kind Kind, ep Endpoint, count int64) Bucket {
	return Bucket{Minute: min, ClientID: client, Kind: kind, Endpoint: ep, Count: count}
}

func TestAggregatePortfolio_TotalsAndSplit(t *testing.T) {
	m0 := time.Date(2026, time.July, 3, 10, 0, 0, 0, time.UTC)
	m1 := m0.Add(time.Minute)
	buckets := []Bucket{
		bkt(m0, "c1", KindAccess, EndpointToken, 5),
		bkt(m0, "c1", KindRefresh, EndpointToken, 2),
		bkt(m1, "c2", KindAccess, EndpointToken, 4),
		bkt(m0, "c1", KindAccess, EndpointIntrospect, 3), // presentation, not issuance
		bkt(m1, "c2", KindAccess, EndpointUserinfo, 1),   // presentation, not issuance
	}
	v := aggregatePortfolio(buckets)

	if v.TotalEvents != 15 {
		t.Errorf("TotalEvents = %d, want 15", v.TotalEvents)
	}
	if v.IssuedTotal != 11 { // 5+2+4 issuance only
		t.Errorf("IssuedTotal = %d, want 11", v.IssuedTotal)
	}
	if v.Introspections != 3 || v.Userinfo != 1 {
		t.Errorf("introspections=%d userinfo=%d, want 3/1", v.Introspections, v.Userinfo)
	}
	if v.ByKind["access"] != 9 || v.ByKind["refresh"] != 2 {
		t.Errorf("by_kind = %+v, want access 9 refresh 2 (issuance only)", v.ByKind)
	}
}

func TestAggregatePortfolio_ByClientSortedDesc(t *testing.T) {
	m0 := time.Date(2026, time.July, 3, 10, 0, 0, 0, time.UTC)
	v := aggregatePortfolio([]Bucket{
		bkt(m0, "small", KindAccess, EndpointToken, 1),
		bkt(m0, "big", KindAccess, EndpointToken, 9),
		bkt(m0, "mid", KindAccess, EndpointToken, 5),
	})
	if len(v.ByClient) != 3 || v.ByClient[0].ClientID != "big" || v.ByClient[2].ClientID != "small" {
		t.Fatalf("by_client = %+v, want big..small (issued desc)", v.ByClient)
	}
}

func TestAggregatePortfolio_TrendAscending(t *testing.T) {
	m0 := time.Date(2026, time.July, 3, 10, 0, 0, 0, time.UTC)
	v := aggregatePortfolio([]Bucket{
		bkt(m0.Add(2*time.Minute), "c1", KindAccess, EndpointToken, 3),
		bkt(m0, "c1", KindAccess, EndpointToken, 1),
		bkt(m0.Add(time.Minute), "c1", KindAccess, EndpointToken, 2),
	})
	if len(v.Trend) != 3 {
		t.Fatalf("trend len = %d, want 3", len(v.Trend))
	}
	if v.Trend[0].Issued != 1 || v.Trend[2].Issued != 3 {
		t.Errorf("trend not ascending by minute: %+v", v.Trend)
	}
}
