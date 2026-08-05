package sqlite

import (
	"context"
	"database/sql"
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
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	ctx := context.Background()
	now := time.Now()
	_ = c.Record(ctx, "", "ip1", "alice", now.Add(-10*time.Second))
	_ = c.Record(ctx, "", "ip1", "bob", now.Add(-5*time.Second))
	_ = c.Record(ctx, "", "ip1", "alice", now.Add(-3*time.Second))

	total, distinct, err := c.Count(ctx, "", "ip1", time.Time{})
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if total != 3 || distinct != 2 {
		t.Errorf("total=%d distinct=%d, want 3,2", total, distinct)
	}
}

func TestSQLiteIPFailureCounter_RecordEmptyIPNoop(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	if err := c.Record(context.Background(), "", "", "alice", time.Now()); err != nil {
		t.Fatalf("Record: %v", err)
	}
}

func TestSQLiteIPFailureCounter_CountRespectsSince(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "", "ip1", "alice", now.Add(-1*time.Hour))
	_ = c.Record(context.Background(), "", "ip1", "bob", now.Add(-1*time.Minute))

	total, distinct, _ := c.Count(context.Background(), "", "ip1", now.Add(-10*time.Minute))
	if total != 1 || distinct != 1 {
		t.Errorf("since filter: total=%d distinct=%d, want 1,1", total, distinct)
	}
}

func TestSQLiteIPFailureCounter_EmptySubjectNotInDistinct(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "", "ip1", "", now.Add(-1*time.Minute))
	_ = c.Record(context.Background(), "", "ip1", "alice", now)
	total, distinct, _ := c.Count(context.Background(), "", "ip1", time.Time{})
	if total != 2 {
		t.Errorf("total = %d, want 2", total)
	}
	if distinct != 1 {
		t.Errorf("distinct = %d, want 1 (empty-subject excluded via NULLIF)", distinct)
	}
}

func TestSQLiteIPFailureCounter_PruneOlder(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	now := time.Now()
	_ = c.Record(context.Background(), "", "ip1", "alice", now.Add(-2*time.Hour))
	_ = c.Record(context.Background(), "", "ip1", "bob", now.Add(-1*time.Minute))
	deleted, _ := c.PruneOlder(context.Background(), now.Add(-1*time.Hour))
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
}

func TestSQLiteIPFailureCounter_ClusterSharedSameDSN(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	a, _ := NewIPFailureCounter(dsn)
	defer func() { _ = a.Close() }()
	b, _ := NewIPFailureCounter(dsn)
	defer func() { _ = b.Close() }()

	_ = a.Record(context.Background(), "", "ip1", "alice", time.Now())
	total, _, _ := b.Count(context.Background(), "", "ip1", time.Time{})
	if total != 1 {
		t.Errorf("b should see a's writes; got %d", total)
	}
}

func TestSQLiteIPFailureCounter_PingFailsAfterClose(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	_ = c.Close()
	if err := c.Ping(context.Background()); err == nil {
		t.Error("Ping post-close should fail")
	}
}

// TestSQLiteIPFailureCounter_TenantIsolation pins improvement-2's storage
// contract: the same ipHash across tenants produces independent counts.
func TestSQLiteIPFailureCounter_TenantIsolation(t *testing.T) {
	t.Parallel()
	c := newIPFailureCounterForTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, r := range []struct {
		tenant, ip, subject string
	}{
		{"t1", "hash-a", "alice"},
		{"t1", "hash-a", "bob"},
		{"t2", "hash-a", "alice"},
	} {
		if err := c.Record(ctx, r.tenant, r.ip, r.subject, now); err != nil {
			t.Fatalf("Record: %v", err)
		}
	}
	total, distinct, err := c.Count(ctx, "t1", "hash-a", time.Time{})
	if err != nil {
		t.Fatalf("Count t1: %v", err)
	}
	if total != 2 || distinct != 2 {
		t.Errorf("t1 count = (%d, %d), want (2, 2) — no t2 leakage", total, distinct)
	}
	total, distinct, err = c.Count(ctx, "t2", "hash-a", time.Time{})
	if err != nil {
		t.Fatalf("Count t2: %v", err)
	}
	if total != 1 || distinct != 1 {
		t.Errorf("t2 count = (%d, %d), want (1, 1)", total, distinct)
	}
}

// TestSQLiteIPFailureCounter_PreTenantSchemaUpgrade mirrors the
// recent_logins upgrade test for ip_failures.
func TestSQLiteIPFailureCounter_PreTenantSchemaUpgrade(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "ipfail.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	oldDDL := `
CREATE TABLE ip_failures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_hash      TEXT    NOT NULL,
    subject_id   TEXT    NOT NULL DEFAULT '',
    ts_unix_ns   INTEGER NOT NULL
);
CREATE INDEX idx_ip_failures_ip_ts
    ON ip_failures(ip_hash, ts_unix_ns);
CREATE INDEX idx_ip_failures_ts
    ON ip_failures(ts_unix_ns);
`
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, oldDDL); err != nil {
		t.Fatalf("seed old schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO ip_failures (ip_hash, subject_id, ts_unix_ns)
        VALUES ('hash-legacy', 'alice', ?)`, time.Now().UnixNano()); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE schema_migrations_ip_failure_counter (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("version table: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_migrations_ip_failure_counter VALUES (1, 'baseline', ?)`, time.Now().UnixNano()); err != nil {
		t.Fatalf("version stamp: %v", err)
	}

	c, err := NewIPFailureCounterWithDB(db)
	if err != nil {
		t.Fatalf("open counter over old schema: %v", err)
	}
	total, distinct, err := c.Count(ctx, "", "hash-legacy", time.Time{})
	if err != nil {
		t.Fatalf("Count legacy: %v", err)
	}
	if total != 1 || distinct != 1 {
		t.Fatalf("legacy row lost or mispartitioned: (%d, %d)", total, distinct)
	}
}
