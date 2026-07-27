package memory

import (
	"context"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/tokenanomaly"
)

var t0 = time.Date(2026, time.July, 3, 9, 0, 0, 0, time.UTC)

func mkFinding(typ string, sev tokenanomaly.Severity, thumb string, last time.Time) tokenanomaly.Finding {
	return tokenanomaly.Finding{
		Type:       typ,
		Severity:   sev,
		Thumbprint: thumb,
		FirstSeen:  last,
		LastSeen:   last,
	}
}

// TestFindingStore_UpsertDedup: re-adding the same (type, thumbprint) updates
// the row (preserving the earliest FirstSeen, advancing LastSeen) instead of
// appending a duplicate.
func TestFindingStore_UpsertDedup(t *testing.T) {
	s := NewFindingStore()
	ctx := context.Background()
	first := mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0)
	_ = s.Add(ctx, first)
	later := mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0.Add(time.Hour))
	_ = s.Add(ctx, later)

	list, _ := s.List(ctx, tokenanomaly.FindingQuery{})
	if len(list) != 1 {
		t.Fatalf("len = %d, want 1 (deduped)", len(list))
	}
	if !list[0].FirstSeen.Equal(t0) {
		t.Errorf("FirstSeen = %v, want earliest %v", list[0].FirstSeen, t0)
	}
	if !list[0].LastSeen.Equal(t0.Add(time.Hour)) {
		t.Errorf("LastSeen = %v, want latest", list[0].LastSeen)
	}
}

// TestFindingStore_SeverityOnlyEscalates: once a row is critical, a later warn
// re-detection must not downgrade it.
func TestFindingStore_SeverityOnlyEscalates(t *testing.T) {
	s := NewFindingStore()
	ctx := context.Background()
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityCritical, "tp1", t0))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0.Add(time.Minute)))
	list, _ := s.List(ctx, tokenanomaly.FindingQuery{})
	if list[0].Severity != tokenanomaly.SeverityCritical {
		t.Errorf("severity = %q, want critical (no downgrade)", list[0].Severity)
	}
}

// TestFindingStore_DifferentTypesAreDistinct: same thumbprint, different type
// are separate rows.
func TestFindingStore_DifferentTypesAreDistinct(t *testing.T) {
	s := NewFindingStore()
	ctx := context.Background()
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingVelocity, tokenanomaly.SeverityCritical, "tp1", t0))
	if list, _ := s.List(ctx, tokenanomaly.FindingQuery{}); len(list) != 2 {
		t.Fatalf("len = %d, want 2 (distinct types)", len(list))
	}
}

// TestFindingStore_EvictsOldestAtCap: a new distinct finding past the cap
// evicts the oldest-inserted, keeping the store bounded.
func TestFindingStore_EvictsOldestAtCap(t *testing.T) {
	s := NewFindingStore(WithMaxFindings(2))
	ctx := context.Background()
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp2", t0.Add(time.Minute)))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp3", t0.Add(2*time.Minute)))
	list, _ := s.List(ctx, tokenanomaly.FindingQuery{})
	if len(list) != 2 {
		t.Fatalf("len = %d, want 2 (cap held)", len(list))
	}
	for _, f := range list {
		if f.Thumbprint == "tp1" {
			t.Fatalf("oldest (tp1) survived eviction: %+v", list)
		}
	}
}

// TestFindingStore_ListFilterAndOrder: List filters by type/severity, orders
// most-recent LastSeen first, and honors Limit.
func TestFindingStore_ListFilterAndOrder(t *testing.T) {
	s := NewFindingStore()
	ctx := context.Background()
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingMultiGeo, tokenanomaly.SeverityWarn, "tp1", t0))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingVelocity, tokenanomaly.SeverityCritical, "tp2", t0.Add(2*time.Minute)))
	_ = s.Add(ctx, mkFinding(tokenanomaly.FindingRateSpike, tokenanomaly.SeverityWarn, "", t0.Add(time.Minute)))

	// Filter by type.
	if got, _ := s.List(ctx, tokenanomaly.FindingQuery{Type: tokenanomaly.FindingVelocity}); len(got) != 1 || got[0].Thumbprint != "tp2" {
		t.Fatalf("type filter = %+v, want just tp2", got)
	}
	// Filter by severity.
	if got, _ := s.List(ctx, tokenanomaly.FindingQuery{Severity: tokenanomaly.SeverityCritical}); len(got) != 1 {
		t.Fatalf("severity filter len = %d, want 1", len(got))
	}
	// Order: newest LastSeen first (tp2 @ +2m, spike @ +1m, tp1 @ 0).
	all, _ := s.List(ctx, tokenanomaly.FindingQuery{})
	if all[0].Thumbprint != "tp2" {
		t.Errorf("first = %+v, want newest tp2", all[0])
	}
	// Limit.
	if got, _ := s.List(ctx, tokenanomaly.FindingQuery{Limit: 2}); len(got) != 2 {
		t.Fatalf("limit=2 returned %d", len(got))
	}
}
