package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
)

func TestMemoryRecentLoginStore_AppendAndRecentRoundtrip(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

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
	// Newest first.
	if got[0].IPHash != "ip3" || got[1].IPHash != "ip2" || got[2].IPHash != "ip1" {
		t.Errorf("order: got %s %s %s, want ip3 ip2 ip1", got[0].IPHash, got[1].IPHash, got[2].IPHash)
	}
}

func TestMemoryRecentLoginStore_AppendEmptySubjectErrors(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	err := s.Append(context.Background(), &anomaly.LoginEntry{Outcome: "failure"})
	if !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestMemoryRecentLoginStore_AppendNilErrors(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	if err := s.Append(context.Background(), nil); !errors.Is(err, anomaly.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestMemoryRecentLoginStore_RecentRespectsSince(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Hour)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})

	got, _ := s.Recent(ctx, "alice", now.Add(-2*time.Minute), 0)
	if len(got) != 1 {
		t.Fatalf("since filter: got %d, want 1 entry newer than 2 min ago", len(got))
	}
}

func TestMemoryRecentLoginStore_RecentRespectsLimit(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
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

func TestMemoryRecentLoginStore_RecentEmptySubjectReturnsNil(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	got, err := s.Recent(context.Background(), "", time.Time{}, 0)
	if err != nil {
		t.Fatalf("Recent(empty): %v", err)
	}
	if got != nil {
		t.Errorf("got %v, want nil", got)
	}
}

func TestMemoryRecentLoginStore_PerSubjectCapEnforced(t *testing.T) {
	t.Parallel()
	// Cap at 3; insert 5 → newest 3 survive.
	s := defaultimpl.NewMemoryRecentLoginStore(defaultimpl.WithRecentLoginPerSubjectCap(3))
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 5 {
		_ = s.Append(ctx, &anomaly.LoginEntry{
			SubjectID: "alice",
			IPHash:    string(rune('a' + i)),
			Timestamp: now.Add(time.Duration(i) * time.Second),
		})
	}
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if len(got) != 3 {
		t.Fatalf("cap: got %d, want 3", len(got))
	}
	// Newest first → 'e', 'd', 'c'.
	if got[0].IPHash != "e" || got[1].IPHash != "d" || got[2].IPHash != "c" {
		t.Errorf("cap kept wrong entries: %v %v %v", got[0].IPHash, got[1].IPHash, got[2].IPHash)
	}
}

func TestMemoryRecentLoginStore_PruneOlderRemovesPastCutoff(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-2 * time.Hour)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "bob", Timestamp: now.Add(-3 * time.Hour)})

	deleted, err := s.PruneOlder(ctx, now.Add(-1*time.Hour))
	if err != nil {
		t.Fatalf("PruneOlder: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted = %d, want 2", deleted)
	}
	// alice keeps her recent entry; bob's bucket disappears (was empty after prune).
	aliceLeft, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if len(aliceLeft) != 1 {
		t.Errorf("alice should have 1 entry, got %d", len(aliceLeft))
	}
	bobLeft, _ := s.Recent(ctx, "bob", time.Time{}, 0)
	if len(bobLeft) != 0 {
		t.Errorf("bob bucket should be cleaned up, got %d entries", len(bobLeft))
	}
}

func TestMemoryRecentLoginStore_PruneOlderZeroIsNoop(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	_ = s.Append(ctx, &anomaly.LoginEntry{SubjectID: "alice", Timestamp: time.Now()})
	deleted, _ := s.PruneOlder(ctx, time.Time{})
	if deleted != 0 {
		t.Errorf("zero cutoff: deleted %d, want 0", deleted)
	}
}

func TestMemoryRecentLoginStore_CallerMutationDoesNotLeak(t *testing.T) {
	t.Parallel()
	// Append's defensive copy prevents the caller from mutating
	// the stored row by holding onto the input pointer.
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	entry := &anomaly.LoginEntry{SubjectID: "alice", IPHash: "original", Timestamp: time.Now()}
	_ = s.Append(ctx, entry)
	entry.IPHash = "MUTATED"
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if got[0].IPHash != "original" {
		t.Errorf("caller mutation leaked: %v", got[0].IPHash)
	}
}
