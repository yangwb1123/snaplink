package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/infrastructure/defaultimpl"
)

func TestMemoryIPFailureCounter_RecordCountRoundtrip(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	ctx := context.Background()
	now := time.Now()
	_ = c.Record(ctx, "ip1", "alice", now.Add(-10*time.Second))
	_ = c.Record(ctx, "ip1", "bob", now.Add(-5*time.Second))
	_ = c.Record(ctx, "ip1", "alice", now.Add(-3*time.Second))

	total, distinct, err := c.Count(ctx, "ip1", time.Time{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 3 || distinct != 2 {
		t.Errorf("total=%d distinct=%d, want 3,2", total, distinct)
	}
}

func TestMemoryIPFailureCounter_RecordEmptyIPNoop(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	if err := c.Record(context.Background(), "", "alice", time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}
	total, _, _ := c.Count(context.Background(), "", time.Time{})
	if total != 0 {
		t.Errorf("empty IP total: %d, want 0", total)
	}
}

func TestMemoryIPFailureCounter_CountRespectsSince(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "alice", now.Add(-1*time.Hour))
	_ = c.Record(context.Background(), "ip1", "bob", now.Add(-1*time.Minute))

	total, distinct, _ := c.Count(context.Background(), "ip1", now.Add(-10*time.Minute))
	if total != 1 || distinct != 1 {
		t.Errorf("since filter: total=%d distinct=%d, want 1,1", total, distinct)
	}
}

func TestMemoryIPFailureCounter_EmptySubjectNotInDistinct(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "", now.Add(-1*time.Minute))
	_ = c.Record(context.Background(), "ip1", "alice", now)
	total, distinct, _ := c.Count(context.Background(), "ip1", time.Time{})
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if distinct != 1 {
		t.Errorf("distinct = %d, want 1 (empty-subject excluded)", distinct)
	}
}

func TestMemoryIPFailureCounter_PruneOlder(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "alice", now.Add(-2*time.Hour))
	_ = c.Record(context.Background(), "ip1", "bob", now.Add(-1*time.Minute))
	_ = c.Record(context.Background(), "ip2", "charlie", now.Add(-3*time.Hour))

	deleted, err := c.PruneOlder(context.Background(), now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("PruneOlder: %v", err)
	}
	if deleted != 2 {
		t.Errorf("deleted = %d, want 2", deleted)
	}
	total, _, _ := c.Count(context.Background(), "ip1", time.Time{})
	if total != 1 {
		t.Errorf("ip1 post-prune total = %d, want 1", total)
	}
	total2, _, _ := c.Count(context.Background(), "ip2", time.Time{})
	if total2 != 0 {
		t.Errorf("ip2 should be cleaned: %d entries", total2)
	}
}

func TestMemoryIPFailureCounter_PruneZeroNoop(t *testing.T) {
	c := defaultimpl.NewMemoryIPFailureCounter()
	_ = c.Record(context.Background(), "ip1", "alice", time.Now())
	deleted, _ := c.PruneOlder(context.Background(), time.Time{})
	if deleted != 0 {
		t.Errorf("zero cutoff: %d, want 0", deleted)
	}
}
