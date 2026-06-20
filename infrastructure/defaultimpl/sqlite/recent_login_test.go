package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
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
	got, err := s.Recent(ctx, "alice", time.Time{}, 0)
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
	s := newRecentLoginStoreForTest(t)
	err := s.Append(context.Background(), &anomaly.LoginEntry{Outcome: "failure"})
	if !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestSQLiteRecentLoginStore_AppendNilErrors(t *testing.T) {
	s := newRecentLoginStoreForTest(t)
	if err := s.Append(context.Background(), nil); !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestSQLiteRecentLoginStore_RecentRespectsSince(t *testing.T) {
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Hour)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})

	got, _ := s.Recent(ctx, "alice", now.Add(-2*time.Minute), 0)
	if len(got) != 1 {
		t.Fatalf("since filter: got %d, want 1", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentRespectsLimit(t *testing.T) {
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 5 {
		_ = s.Append(ctx, &anomaly.LoginEntry{
			SubjectID: "alice",
			Timestamp: now.Add(-time.Duration(i) * time.Second),
		})
	}
	got, _ := s.Recent(ctx, "alice", time.Time{}, 2)
	if len(got) != 2 {
		t.Fatalf("limit: got %d, want 2", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentDefaultsTo100(t *testing.T) {
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
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if len(got) != 100 {
		t.Errorf("default cap: got %d, want 100", len(got))
	}
}

func TestSQLiteRecentLoginStore_RecentEmptySubjectReturnsNil(t *testing.T) {
	s := newRecentLoginStoreForTest(t)
	got, err := s.Recent(context.Background(), "", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent(empty): %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestSQLiteRecentLoginStore_PruneOlderRemovesPastCutoff(t *testing.T) {
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
	s := newRecentLoginStoreForTest(t)
	deleted, _ := s.PruneOlder(context.Background(), time.Time{})
	if deleted != 0 {
		t.Errorf("zero cutoff: %d, want 0", deleted)
	}
}

func TestSQLiteRecentLoginStore_GeoFieldsRoundtrip(t *testing.T) {
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
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if got[0].CountryCode != "US" || got[0].Latitude != 37.7749 || got[0].Longitude != -122.4194 {
		t.Errorf("geo fields: %+v", got[0])
	}
}

func TestSQLiteRecentLoginStore_TimestampRoundtripPreservesUTC(t *testing.T) {
	s := newRecentLoginStoreForTest(t)
	ctx := context.Background()
	ts := time.Date(2026, 5, 22, 12, 34, 56, 0, time.UTC)
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: ts})
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if !got[0].Timestamp.Equal(ts) {
		t.Errorf("ts roundtrip: got %v, want %v", got[0].Timestamp, ts)
	}
	if got[0].Timestamp.Location() != time.UTC {
		t.Errorf("location should be UTC, got %v", got[0].Timestamp.Location())
	}
}

func TestSQLiteRecentLoginStore_ClusterSharedSameDSN(t *testing.T) {
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
	got, _ := b.Recent(context.Background(), "alice", time.Time{}, 0)
	if len(got) != 1 || got[0].IPHash != "shared" {
		t.Errorf("b should see entry written by a: %v", got)
	}
}

func TestSQLiteRecentLoginStore_PingFailsAfterClose(t *testing.T) {
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
	s := newRecentLoginStoreForTest(t)
	if err := s.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close should no-op: %v", err)
	}
}
