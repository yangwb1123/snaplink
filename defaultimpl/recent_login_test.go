package defaultimpl_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/geo"
)

func TestMemoryRecentLoginStore_AppendAndRecentRoundtrip(t *testing.T) {
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

	entries := []*sso.LoginEntry{
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
	s := defaultimpl.NewMemoryRecentLoginStore()
	err := s.Append(context.Background(), &sso.LoginEntry{Outcome: "failure"})
	if !errors.Is(err, sso.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestMemoryRecentLoginStore_AppendNilErrors(t *testing.T) {
	s := defaultimpl.NewMemoryRecentLoginStore()
	if err := s.Append(context.Background(), nil); !errors.Is(err, sso.ErrInvalidLoginEntry) {
		t.Fatalf("got %v, want ErrInvalidLoginEntry", err)
	}
}

func TestMemoryRecentLoginStore_RecentRespectsSince(t *testing.T) {
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Hour)})
	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})

	got, _ := s.Recent(ctx, "alice", now.Add(-2*time.Minute), 0)
	if len(got) != 1 {
		t.Fatalf("since filter: got %d, want 1 entry newer than 2 min ago", len(got))
	}
}

func TestMemoryRecentLoginStore_RecentRespectsLimit(t *testing.T) {
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 5 {
		_ = s.Append(ctx, &sso.LoginEntry{
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
	// Cap at 3; insert 5 → newest 3 survive.
	s := defaultimpl.NewMemoryRecentLoginStore(defaultimpl.WithRecentLoginPerSubjectCap(3))
	ctx := context.Background()
	now := time.Now().UTC()
	for i := range 5 {
		_ = s.Append(ctx, &sso.LoginEntry{
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
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	now := time.Now().UTC()

	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-2 * time.Hour)})
	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "alice", Timestamp: now.Add(-1 * time.Minute)})
	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "bob", Timestamp: now.Add(-3 * time.Hour)})

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
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	_ = s.Append(ctx, &sso.LoginEntry{SubjectID: "alice", Timestamp: time.Now()})
	deleted, _ := s.PruneOlder(ctx, time.Time{})
	if deleted != 0 {
		t.Errorf("zero cutoff: deleted %d, want 0", deleted)
	}
}

func TestMemoryRecentLoginStore_CallerMutationDoesNotLeak(t *testing.T) {
	// Append's defensive copy prevents the caller from mutating
	// the stored row by holding onto the input pointer.
	s := defaultimpl.NewMemoryRecentLoginStore()
	ctx := context.Background()
	entry := &sso.LoginEntry{SubjectID: "alice", IPHash: "original", Timestamp: time.Now()}
	_ = s.Append(ctx, entry)
	entry.IPHash = "MUTATED"
	got, _ := s.Recent(ctx, "alice", time.Time{}, 0)
	if got[0].IPHash != "original" {
		t.Errorf("caller mutation leaked: %v", got[0].IPHash)
	}
}

// --- HashLoginEntry ---

func TestHashLoginEntry_PopulatesAllFields(t *testing.T) {
	now := time.Now().UTC()
	event := &sso.LoginEvent{
		SubjectID: "alice",
		ClientID:  "web",
		Outcome:   "success",
		RemoteIP:  "10.0.0.1",
		UserAgent: "Mozilla/5.0",
		Geo: &geo.GeoInfo{
			CountryCode: "US",
			Latitude:    37.7749,
			Longitude:   -122.4194,
		},
		Timestamp: now,
	}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry == nil {
		t.Fatal("HashLoginEntry nil for valid event")
	}
	if entry.SubjectID != "alice" || entry.ClientID != "web" || entry.Outcome != "success" {
		t.Errorf("scalar fields: %+v", entry)
	}
	if entry.IPHash == "" || entry.IPHash == "10.0.0.1" {
		t.Errorf("IPHash should be salted hash, got %q", entry.IPHash)
	}
	if entry.UAFingerprintHash == "" {
		t.Errorf("UAFingerprintHash should be populated for non-empty UA")
	}
	if entry.CountryCode != "US" || entry.Latitude != 37.7749 || entry.Longitude != -122.4194 {
		t.Errorf("geo fields: %+v", entry)
	}
	if !entry.Timestamp.Equal(now) {
		t.Errorf("timestamp drift")
	}
}

func TestHashLoginEntry_NilEventReturnsNil(t *testing.T) {
	if got := defaultimpl.HashLoginEntry(nil, []byte("salt")); got != nil {
		t.Errorf("nil event: got %v, want nil", got)
	}
}

func TestHashLoginEntry_EmptySubjectReturnsNil(t *testing.T) {
	event := &sso.LoginEvent{Outcome: "failure"}
	if got := defaultimpl.HashLoginEntry(event, []byte("salt")); got != nil {
		t.Errorf("empty subject: got %v, want nil", got)
	}
}

func TestHashLoginEntry_EmptyUASkipsUAHash(t *testing.T) {
	event := &sso.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry.UAFingerprintHash != "" {
		t.Errorf("empty UA: should not hash, got %q", entry.UAFingerprintHash)
	}
}

func TestHashLoginEntry_NilGeoSkipsGeoFields(t *testing.T) {
	event := &sso.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	entry := defaultimpl.HashLoginEntry(event, []byte("salt"))
	if entry.CountryCode != "" || entry.Latitude != 0 || entry.Longitude != 0 {
		t.Errorf("nil geo: should leave geo fields zero, got %+v", entry)
	}
}

func TestHashLoginEntry_SaltAffectsIPHash(t *testing.T) {
	event := &sso.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1"}
	a := defaultimpl.HashLoginEntry(event, []byte("salt-a"))
	b := defaultimpl.HashLoginEntry(event, []byte("salt-b"))
	if a.IPHash == b.IPHash {
		t.Errorf("different salts should produce different IP hashes; both = %q", a.IPHash)
	}
}

func TestHashLoginEntry_SameSubjectSameUAStableHash(t *testing.T) {
	// Replay invariant: two events with same subject + UA + salt
	// produce same fingerprint, so the new-device detector can
	// compare across login events.
	event1 := &sso.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.1", UserAgent: "Browser/1"}
	event2 := &sso.LoginEvent{SubjectID: "alice", RemoteIP: "10.0.0.2", UserAgent: "Browser/1"}
	a := defaultimpl.HashLoginEntry(event1, []byte("salt"))
	b := defaultimpl.HashLoginEntry(event2, []byte("salt"))
	if a.UAFingerprintHash != b.UAFingerprintHash {
		t.Errorf("same subject + same UA should produce same hash: %q vs %q",
			a.UAFingerprintHash, b.UAFingerprintHash)
	}
}

func TestHashLoginEntry_DifferentSubjectsDifferentUAHash(t *testing.T) {
	// Privacy invariant: same UA across two users produces
	// different hashes (per-subject salt).
	event1 := &sso.LoginEvent{SubjectID: "alice", UserAgent: "Browser/1"}
	event2 := &sso.LoginEvent{SubjectID: "bob", UserAgent: "Browser/1"}
	a := defaultimpl.HashLoginEntry(event1, []byte("salt"))
	b := defaultimpl.HashLoginEntry(event2, []byte("salt"))
	if a.UAFingerprintHash == b.UAFingerprintHash {
		t.Errorf("different subjects with same UA should produce different hashes; both = %q",
			a.UAFingerprintHash)
	}
}
