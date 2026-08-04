package memory

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
)

var ctx = context.Background()

func dayOf(year int, month time.Month, day int) time.Time {
	return time.Date(year, month, day, 0, 0, 0, 0, time.UTC)
}

func TestUsage_hit(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	start := dayOf(2026, time.January, 15)
	a.Record(&metering.TenantUsage{
		TenantID:      "t1",
		Period:        metering.PeriodDay,
		PeriodStart:   start,
		Logins:        42,
		TokensIssued:  100,
		ActiveUsers:   20,
		MFAChallenges: 5,
	})

	u, err := a.Usage(ctx, "t1", metering.PeriodDay, start)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Logins != 42 {
		t.Errorf("Logins = %d, want 42", u.Logins)
	}
	if u.TokensIssued != 100 {
		t.Errorf("TokensIssued = %d, want 100", u.TokensIssued)
	}
	if u.ActiveUsers != 20 {
		t.Errorf("ActiveUsers = %d, want 20", u.ActiveUsers)
	}
	if u.MFAChallenges != 5 {
		t.Errorf("MFAChallenges = %d, want 5", u.MFAChallenges)
	}
}

func TestUsage_miss_returns_zeros(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	u, err := a.Usage(ctx, "unknown-tenant", metering.PeriodDay, dayOf(2026, time.January, 1))
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Logins != 0 || u.TokensIssued != 0 || u.ActiveUsers != 0 || u.MFAChallenges != 0 {
		t.Errorf("expected all-zero for miss, got %+v", u)
	}
	if u.TenantID != "unknown-tenant" {
		t.Errorf("TenantID = %q, want %q", u.TenantID, "unknown-tenant")
	}
}

func TestUsage_midday_timestamp_truncated(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	// Record is stored with midnight; query uses a midday timestamp — should match.
	start := dayOf(2026, time.March, 10)
	a.Record(&metering.TenantUsage{
		TenantID:    "t2",
		Period:      metering.PeriodDay,
		PeriodStart: start,
		Logins:      7,
	})

	midday := time.Date(2026, time.March, 10, 14, 30, 0, 0, time.UTC)
	u, err := a.Usage(ctx, "t2", metering.PeriodDay, midday)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Logins != 7 {
		t.Errorf("Logins = %d, want 7 (truncation should match midnight record)", u.Logins)
	}
}

func TestUsage_month_period(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	a.Record(&metering.TenantUsage{
		TenantID:    "t3",
		Period:      metering.PeriodMonth,
		PeriodStart: time.Date(2026, time.February, 1, 0, 0, 0, 0, time.UTC),
		Logins:      300,
	})

	// Query with a non-first-day date; truncation should find the Feb record.
	u, err := a.Usage(ctx, "t3", metering.PeriodMonth, time.Date(2026, time.February, 17, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Logins != 300 {
		t.Errorf("Logins = %d, want 300", u.Logins)
	}
}

// TestUsage_activeClients verifies ActiveClients rides through the
// record-and-copy path per tenant like every other counter: two distinct
// clients recorded for tenant A, one for tenant B (the memory aggregator
// stores pre-computed usage — the distinct-client dedup happens in the
// audit-log-backed aggregator).
func TestUsage_activeClients(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	start := dayOf(2026, time.August, 15)
	a.Record(&metering.TenantUsage{
		TenantID:      "tenant-a",
		Period:        metering.PeriodDay,
		PeriodStart:   start,
		ActiveClients: 2,
	})
	a.Record(&metering.TenantUsage{
		TenantID:      "tenant-b",
		Period:        metering.PeriodDay,
		PeriodStart:   start,
		ActiveClients: 1,
	})

	ua, err := a.Usage(ctx, "tenant-a", metering.PeriodDay, start)
	if err != nil {
		t.Fatalf("Usage(tenant-a): %v", err)
	}
	if ua.ActiveClients != 2 {
		t.Errorf("tenant-a ActiveClients = %d, want 2", ua.ActiveClients)
	}
	ub, err := a.Usage(ctx, "tenant-b", metering.PeriodDay, start)
	if err != nil {
		t.Fatalf("Usage(tenant-b): %v", err)
	}
	if ub.ActiveClients != 1 {
		t.Errorf("tenant-b ActiveClients = %d, want 1", ub.ActiveClients)
	}
}

func TestTopTenants_ordering(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	start := dayOf(2026, time.April, 1)
	a.Record(&metering.TenantUsage{TenantID: "low", Period: metering.PeriodDay, PeriodStart: start, Logins: 5})
	a.Record(&metering.TenantUsage{TenantID: "high", Period: metering.PeriodDay, PeriodStart: start, Logins: 500})
	a.Record(&metering.TenantUsage{TenantID: "mid", Period: metering.PeriodDay, PeriodStart: start, Logins: 50})

	tops, err := a.TopTenants(ctx, metering.PeriodDay, start, 10)
	if err != nil {
		t.Fatalf("TopTenants: %v", err)
	}
	if len(tops) != 3 {
		t.Fatalf("len = %d, want 3", len(tops))
	}
	if tops[0].TenantID != "high" || tops[1].TenantID != "mid" || tops[2].TenantID != "low" {
		t.Errorf("wrong order: %v %v %v", tops[0].TenantID, tops[1].TenantID, tops[2].TenantID)
	}
}

func TestTopTenants_limit(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	start := dayOf(2026, time.May, 1)
	for i := 0; i < 5; i++ {
		a.Record(&metering.TenantUsage{
			TenantID:    string(rune('a' + i)),
			Period:      metering.PeriodDay,
			PeriodStart: start,
			Logins:      int64(i + 1),
		})
	}

	tops, err := a.TopTenants(ctx, metering.PeriodDay, start, 2)
	if err != nil {
		t.Fatalf("TopTenants: %v", err)
	}
	if len(tops) != 2 {
		t.Errorf("len = %d, want 2 (limit respected)", len(tops))
	}
}

func TestTopTenants_different_period_excluded(t *testing.T) {
	t.Parallel()
	a := NewAggregator()
	jan := dayOf(2026, time.January, 1)
	feb := dayOf(2026, time.February, 1)
	a.Record(&metering.TenantUsage{TenantID: "t1", Period: metering.PeriodMonth, PeriodStart: jan, Logins: 99})
	a.Record(&metering.TenantUsage{TenantID: "t2", Period: metering.PeriodMonth, PeriodStart: feb, Logins: 1})

	tops, err := a.TopTenants(ctx, metering.PeriodMonth, jan, 10)
	if err != nil {
		t.Fatalf("TopTenants: %v", err)
	}
	if len(tops) != 1 || tops[0].TenantID != "t1" {
		t.Errorf("wrong results: %v", tops)
	}
}
