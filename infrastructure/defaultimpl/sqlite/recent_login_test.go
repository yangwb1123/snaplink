package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
)

func newRecentLoginStoreForTest(t *testing.T) *RecentLoginStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "recent.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	s, err := NewRecentLoginStore(dsn)
	if err != nil {
		t.Fatalf("NewRecentLoginStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestSQLiteRecentLoginStore_AppendAndRecent(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	entries := []*anomaly.LoginEntry{
		{SubjectID: "alice", Outcome: "success", IPHash: "ip1", Timestamp: now.Add(-30 * time.Second)},
		{SubjectID: "alice", Outcome: "failure", IPHash: "ip2", Timestamp: now.Add(-20 * time.Second)},
		{SubjectID: "alice", Outcome: "success", IPHash: "ip3", Timestamp: now.Add(-10 * time.Second)},
	}
	for _, e := range entries {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	got, err := s.Recent(ctx, "", "alice", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("len = %d, want 3", len(got))
	}
	if got[0].IPHash != "ip3" || got[1].IPHash != "ip2" || got[2].IPHash != "ip1" {
		t.Errorf("order: %s %s %s, want ip3 ip2 ip1", got[0].IPHash, got[1].IPHash, got[2].IPHash)
	}
}

func TestSQLiteRecentLoginStore_AppendEmptySubjectErrors(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	err := s.Append(context.Background(), &anomaly.LoginEntry{Outcome: "failure"})
	if !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestSQLiteRecentLoginStore_AppendNilErrors(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	if err := s.Append(context.Background(), nil); !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestSQLiteRecentLoginStore_RecentRespectsSince(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Hour)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})

	got, _ := s.Recent(ctx, "", "alice", now.Add(-2*time.Minute), 0)
	if len(got) != 1 {
		t.Fatalf("since filter: got %d, want 1", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentRespectsLimit(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 5 {
		_ = s.Append(ctx, &anomaly.LoginEntry{
			SubjectID: "alice",
			Timestamp: now.Add(-time.Duration(i) * time.Second),
		})
	}
	got, _ := s.Recent(ctx, "", "alice", time.Time{}, 2)
	if len(got) != 2 {
		t.Fatalf("limit: got %d, want 2", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentDefaultsTo100(t *testing.T) {
	t.Parallel()
	// limit <= 0 → backend cap = 100 (matches SPI contract).
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 150 {
		_ = s.Append(ctx, &anomaly.LoginEntry{
			SubjectID: "alice",
			Timestamp: now.Add(-time.Duration(i) * time.Millisecond),
		})
	}
	got, _ := s.Recent(ctx, "", "alice", time.Time{}, 0)
	if len(got) != 100 {
		t.Errorf("default cap: got %d, want 100", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentEmptySubjectReturnsNil(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	got, err := s.Recent(context.Background(), "", "", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent(empty): %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestSQLiteRecentLoginStore_PruneOlderRemovesPastCutoff(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-2 * time.Hour)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})

	deleted, err := s.PruneOlder(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("PruneOlder: %v", err)
	}
	if deleted != 1 {
		t.Errorf("deleted = %d, want 1", deleted)
	}
}

func TestSQLiteRecentLoginStore_PruneOlderZeroIsNoop(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	deleted, _ := s.PruneOlder(context.Background(), time.Time{})
	if deleted != 0 {
		t.Errorf("zero cutoff: %d, want 0", deleted)
	}
}

func TestSQLiteRecentLoginStore_GeoFieldsRoundtrip(t *testing.T) {
	t.Parallel()
	// Latitude/longitude/country preserved across Append→Recent —
	// impossible-travel detector reads them directly.
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	_ = s.Append(ctx, &anomaly.LoginEntry{
		SubjectID:   "alice",
		CountryCode: "US",
		Latitude:    37.7749,
		Longitude:   -122.4194,
		Timestamp:   time.Now().UTC(),
	})
	got, _ := s.Recent(ctx, "", "alice", time.Time{}, 0)
	if got[0].CountryCode != "US" || got[0].Latitude != 37.7749 || got[0].Longitude != -122.4194 {
		t.Errorf("geo fields: %+v", got[0])
	}
}

func TestSQLiteRecentLoginStore_TimestampRoundtripPreservesUTC(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	ts := time.Date(2026, 5, 22, 12, 34, 56, 0, time.UTC)
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: ts})
	got, _ := s.Recent(ctx, "", "alice", time.Time{}, 0)
	if !got[0].Timestamp.Equal(ts) {
		t.Errorf("ts roundtrip: got %v, want %v", got[0].Timestamp, ts)
	}
	if got[0].Timestamp.Location() != time.UTC {
		t.Errorf("location should be UTC, got %v", got[0].Timestamp.Location())
	}
}

func TestSQLiteRecentLoginStore_ClusterSharedSameDSN(t *testing.T) {
	t.Parallel()
	// Two stores on the same DSN — entries written by store A
	// visible to store B (cluster-shared semantic). This is the
	// difference from the memory peer.
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "shared.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	a, err := NewRecentLoginStore(dsn)
	if err != nil {
		t.Fatalf("a: %v", err)
	}
	defer func() { _ = a.Close() }()
	b, err := NewRecentLoginStore(dsn)
	if err != nil {
		t.Fatalf("b: %v", err)
	}
	defer func() { _ = b.Close() }()

	if err := a.Append(context.Background(), &anomaly.LoginEntry{
		SubjectID: "alice",
		IPHash:    "shared",
		Timestamp: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("a.Append: %v", err)
	}
	got, _ := b.Recent(context.Background(), "", "alice", time.Time{}, 0)
	if len(got) != 1 || got[0].IPHash != "shared" {
		t.Errorf("b should see entry written by a: %v", got)
	}
}

func TestSQLiteRecentLoginStore_PingFailsAfterClose(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatalf("Ping pre-close: %v", err)
	}
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Error("Ping post-close should fail")
	}
}

func TestSQLiteRecentLoginStore_DoubleCloseIsNoop(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close should no-op: %v", err)
	}
}

// TestSQLiteRecentLoginStore_TenantIsolation pins improvement-2's storage
// contract: the same SubjectID in different tenants never shares entries.
func TestSQLiteRecentLoginStore_TenantIsolation(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, e := range []*anomaly.LoginEntry{
		{TenantID: "t1", SubjectID: "alice", Outcome: "success", IPHash: "ip-t1", Timestamp: now.Add(-30 * time.Second)},
		{TenantID: "t2", SubjectID: "alice", Outcome: "success", IPHash: "ip-t2", Timestamp: now.Add(-20 * time.Second)},
		{TenantID: "t1", SubjectID: "alice", Outcome: "failure", IPHash: "ip-t1b", Timestamp: now.Add(-10 * time.Second)},
	} {
		if err := s.Append(ctx, e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	got, err := s.Recent(ctx, "t1", "alice", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent t1: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("t1 entries = %d, want 2 (no t2 leakage)", len(got))
	}
	for _, e := range got {
		if e.TenantID != "t1" {
			t.Errorf("leaked entry tenant = %q, want t1", e.TenantID)
		}
	}
	got, err = s.Recent(ctx, "t2", "alice", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent t2: %v", err)
	}
	if len(got) != 1 || got[0].IPHash != "ip-t2" {
		t.Fatalf("t2 entries = %v, want exactly ip-t2", got)
	}
}

// TestSQLiteRecentLoginStore_RecentUsesTenantIndex pins the tenant-leading
// index: the canonical Recent query must be served by
// idx_recent_logins_tenant_subject_ts (plan-text containment, not exact
// match), per the design's T6 acceptance.
func TestSQLiteRecentLoginStore_RecentUsesTenantIndex(t *testing.T) {
	t.Parallel()
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	rows, err := s.db.QueryContext(ctx, `EXPLAIN QUERY PLAN
        SELECT tenant_id, subject_id, ts_unix_ns FROM recent_logins
         WHERE tenant_id = ? AND subject_id = ?
         ORDER BY ts_unix_ns DESC LIMIT 10`, "t1", "alice")
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer func() { _ = rows.Close() }()
	plan := ""
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("scan plan: %v", err)
		}
		plan += detail + "\n"
	}
	if !strings.Contains(plan, "idx_recent_logins_tenant_subject_ts") {
		t.Errorf("query plan does not use the tenant-subject index:\n%s", plan)
	}
	if strings.Contains(plan, "idx_recent_logins_subject_ts") {
		t.Errorf("query plan still uses the old cross-tenant index:\n%s", plan)
	}
}

// TestSQLiteRecentLoginStore_PreTenantSchemaUpgrade constructs the
// pre-migration schema (old DDL + v1 stamp), opens the store, and asserts
// the migration added the column and swapped the index while preserving
// legacy rows with an empty tenant partition.
func TestSQLiteRecentLoginStore_PreTenantSchemaUpgrade(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "recent.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	oldDDL := `
CREATE TABLE recent_logins (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_id            TEXT    NOT NULL,
    client_id             TEXT    NOT NULL DEFAULT '',
    outcome               TEXT    NOT NULL,
    ip_hash               TEXT    NOT NULL DEFAULT '',
    country_code          TEXT    NOT NULL DEFAULT '',
    latitude              REAL    NOT NULL DEFAULT 0,
    longitude             REAL    NOT NULL DEFAULT 0,
    ua_fingerprint_hash   TEXT    NOT NULL DEFAULT '',
    ts_unix_ns            INTEGER NOT NULL
);
CREATE INDEX idx_recent_logins_subject_ts
    ON recent_logins(subject_id, ts_unix_ns DESC);
CREATE INDEX idx_recent_logins_ts
    ON recent_logins(ts_unix_ns);
`
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, oldDDL); err != nil {
		t.Fatalf("seed old schema: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO recent_logins
        (subject_id, client_id, outcome, ts_unix_ns) VALUES ('legacy', '', 'success', ?)`,
		time.Now().UnixNano()); err != nil {
		t.Fatalf("seed legacy row: %v", err)
	}
	// Stamp the v1 version so the migration table starts at v2.
	if _, err := db.ExecContext(ctx,
		`CREATE TABLE schema_migrations_recent_login (
            version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at INTEGER NOT NULL)`); err != nil {
		t.Fatalf("version table: %v", err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO schema_migrations_recent_login VALUES (1, 'baseline', ?)`, time.Now().UnixNano()); err != nil {
		t.Fatalf("version stamp: %v", err)
	}

	s, err := NewRecentLoginStoreWithDB(db)
	if err != nil {
		t.Fatalf("open store over old schema: %v", err)
	}
	got, err := s.Recent(ctx, "", "legacy", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent legacy: %v", err)
	}
	if len(got) != 1 || got[0].SubjectID != "legacy" {
		t.Fatalf("legacy row lost or mispartitioned: %v", got)
	}
	// New writes land in a tenant partition and stay isolated.
	if err := s.Append(ctx, &anomaly.LoginEntry{TenantID: "t1", SubjectID: "legacy", Outcome: "success", Timestamp: time.Now()}); err != nil {
		t.Fatalf("Append post-migration: %v", err)
	}
	got, err = s.Recent(ctx, "t1", "legacy", time.Time{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("post-migration tenant entries = %d, want 1", len(got))
	}
}
