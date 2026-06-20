package sqlite

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func newIPFailureCounterForTest(t *testing.T) *IPFailureCounter {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "ipf.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	c, err := NewIPFailureCounter(dsn)
	if err != nil {
		t.Fatalf("NewIPFailureCounter: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestSQLiteIPFailureCounter_RecordCountRoundtrip(t *testing.T) {
	c := newIPFailureCounterForTest(t)
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

func TestSQLiteIPFailureCounter_RecordEmptyIPNoop(t *testing.T) {
	c := newIPFailureCounterForTest(t)
	if err := c.Record(context.Background(), "", "alice", time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestSQLiteIPFailureCounter_CountRespectsSince(t *testing.T) {
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "alice", now.Add(-1*time.Hour))
	_ = c.Record(context.Background(), "ip1", "bob", now.Add(-1*time.Minute))

	total, distinct, _ := c.Count(context.Background(), "ip1", now.Add(-10*time.Minute))
	if total != 1 || distinct != 1 {
		t.Errorf("since filter: total=%d distinct=%d, want 1,1", total, distinct)
	}
}

func TestSQLiteIPFailureCounter_EmptySubjectNotInDistinct(t *testing.T) {
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "", now.Add(-1*time.Minute))
	_ = c.Record(context.Background(), "ip1", "alice", now)
	total, distinct, _ := c.Count(context.Background(), "ip1", time.Time{})
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if distinct != 1 {
		t.Errorf("distinct = %d, want 1 (empty-subject excluded via NULLIF)", distinct)
	}
}

func TestSQLiteIPFailureCounter_PruneOlder(t *testing.T) {
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "ip1", "alice", now.Add(-2*time.Hour))
	_ = c.Record(context.Background(), "ip1", "bob", now.Add(-1*time.Minute))
	deleted, _ := c.PruneOlder(context.Background(), now.Add(-1*time.Hour))
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
}

func TestSQLiteIPFailureCounter_ClusterSharedSameDSN(t *testing.T) {
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	a, _ := NewIPFailureCounter(dsn)
	defer func() { _ = a.Close() }()
	b, _ := NewIPFailureCounter(dsn)
	defer func() { _ = b.Close() }()

	_ = a.Record(context.Background(), "ip1", "alice", time.Now())
	total, _, _ := b.Count(context.Background(), "ip1", time.Time{})
	if total != 1 {
		t.Errorf("b should see a's writes; got %d", total)
	}
}

func TestSQLiteIPFailureCounter_PingFailsAfterClose(t *testing.T) {
	c := newIPFailureCounterForTest(t)
	_ = c.Close()
	if err := c.Ping(context.Background()); err == nil {
		t.Error("Ping post-close should fail")
	}
}
