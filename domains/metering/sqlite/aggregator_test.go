package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/platform/audit"
	auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"
)

// TestAggregator_basic seeds the audit DB via the real audit/sqlite.Sink
// (which runs the v2 migration and writes tenant_id), then verifies the
// aggregator returns the expected counts.
func TestAggregator_basic(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := "file::memory:?cache=shared&mode=rwc"

	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("audit Sink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	day := time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC)
	tenantID := "acme"

	// Seed events: 3 successful logins for acme, 1 for other tenant,
	// 2 token_issued, 1 mfa_required.
	events := []*audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID, ActorID: "alice"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID, ActorID: "bob"},
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID, ActorID: "alice"}, // duplicate actor
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: "other", ActorID: "carol"},
		{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID},
		{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID},
		{Type: audit.EventMFARequired, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: tenantID},
	}
	for _, e := range events {
		if err := sink.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	agg := NewWithDB(sink.DB())
	u, err := agg.Usage(ctx, tenantID, metering.PeriodDay, day)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if u.Logins != 3 {
		t.Errorf("Logins = %d, want 3", u.Logins)
	}
	if u.ActiveUsers != 2 {
		t.Errorf("ActiveUsers = %d, want 2 (alice deduped)", u.ActiveUsers)
	}
	if u.TokensIssued != 2 {
		t.Errorf("TokensIssued = %d, want 2", u.TokensIssued)
	}
	if u.MFAChallenges != 1 {
		t.Errorf("MFAChallenges = %d, want 1", u.MFAChallenges)
	}
	if u.TenantID != tenantID {
		t.Errorf("TenantID = %q, want %q", u.TenantID, tenantID)
	}
}

// TestAggregator_activeClients verifies ActiveClients counts distinct
// client_ids per tenant within the period: two clients under tenant A
// (deduped across repeat events) and one under tenant B, isolated from
// each other.
func TestAggregator_activeClients(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := "file::memory:?cache=shared&mode=rwc"

	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("audit Sink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	// Unique day + tenant ids: the package tests share one in-memory DB
	// (cache=shared), so the window must not overlap other tests' seeds.
	day := time.Date(2026, time.August, 15, 0, 0, 0, 0, time.UTC)

	events := []*audit.Event{
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: "tenant-a", ActorID: "alice", ClientID: "web-app"},
		{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: "tenant-a", ClientID: "batch-job"},
		{Type: audit.EventTokenIssued, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: "tenant-a", ClientID: "batch-job"}, // duplicate client
		{Type: audit.EventLogin, Outcome: audit.OutcomeSuccess, Timestamp: day, TenantID: "tenant-b", ActorID: "carol", ClientID: "mobile"},
	}
	for _, e := range events {
		if err := sink.Record(ctx, e); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}

	agg := NewWithDB(sink.DB())
	ua, err := agg.Usage(ctx, "tenant-a", metering.PeriodDay, day)
	if err != nil {
		t.Fatalf("Usage(tenant-a): %v", err)
	}
	if ua.ActiveClients != 2 {
		t.Errorf("tenant-a ActiveClients = %d, want 2 (batch-job deduped)", ua.ActiveClients)
	}
	ub, err := agg.Usage(ctx, "tenant-b", metering.PeriodDay, day)
	if err != nil {
		t.Fatalf("Usage(tenant-b): %v", err)
	}
	if ub.ActiveClients != 1 {
		t.Errorf("tenant-b ActiveClients = %d, want 1", ub.ActiveClients)
	}

	// TopTenants shares fillTenantMetrics — the leaderboard rows must carry
	// the same distinct-client counts.
	tops, err := agg.TopTenants(ctx, metering.PeriodDay, day, 10)
	if err != nil {
		t.Fatalf("TopTenants: %v", err)
	}
	got := map[string]int64{}
	for _, u := range tops {
		got[u.TenantID] = u.ActiveClients
	}
	if got["tenant-a"] != 2 || got["tenant-b"] != 1 {
		t.Errorf("TopTenants ActiveClients = %v, want tenant-a:2 tenant-b:1", got)
	}
}

// TestAggregator_topTenants verifies TopTenants returns tenants sorted by
// login count and respects the limit.
func TestAggregator_topTenants(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	dsn := "file::memory:?cache=shared&mode=rwc&_txlock=exclusive"

	sink, err := auditsqlite.New(dsn)
	if err != nil {
		t.Fatalf("audit Sink: %v", err)
	}
	defer func() { _ = sink.Close() }()

	day := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)

	seed := func(tid string, n int) {
		for i := 0; i < n; i++ {
			e := &audit.Event{
				Type:      audit.EventLogin,
				Outcome:   audit.OutcomeSuccess,
				Timestamp: day,
				TenantID:  tid,
				ActorID:   "user",
			}
			if err := sink.Record(ctx, e); err != nil {
				t.Fatalf("Record: %v", err)
			}
		}
	}
	seed("big", 10)
	seed("small", 2)
	seed("medium", 5)

	agg := NewWithDB(sink.DB())
	tops, err := agg.TopTenants(ctx, metering.PeriodDay, day, 2)
	if err != nil {
		t.Fatalf("TopTenants: %v", err)
	}
	if len(tops) != 2 {
		t.Fatalf("len = %d, want 2", len(tops))
	}
	if tops[0].TenantID != "big" {
		t.Errorf("top tenant = %q, want %q", tops[0].TenantID, "big")
	}
	if tops[1].TenantID != "medium" {
		t.Errorf("second tenant = %q, want %q", tops[1].TenantID, "medium")
	}
}
