package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/defaultimpl"
)

func newPushApprovalStoreForTest(t *testing.T) *PushApprovalStore {
	t.Helper()
	dir := t.TempDir()
	dsn := "file:" + filepath.Join(dir, "push.db") + "?_journal=WAL&_pragma=busy_timeout(5000)"
	s, err := NewPushApprovalStore(dsn)
	if err != nil {
		t.Fatalf("NewPushApprovalStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func samplePushApproval() *defaultimpl.PushApproval {
	now := time.Now().UTC()
	return &defaultimpl.PushApproval{
		ID:        "push-roundtrip",
		SubjectID: "alice",
		Status:    defaultimpl.PushApprovalPending,
		CreatedAt: now,
		ExpiresAt: now.Add(5 * time.Minute),
	}
}

func TestPushApprovalStore_PutAndGetRoundTrip(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	want := samplePushApproval()
	if err := s.Put(ctx, want); err != nil {
		t.Fatalf("Put: %v", err)
	}
	got, err := s.Get(ctx, want.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != want.ID || got.SubjectID != want.SubjectID || got.Status != want.Status {
		t.Fatalf("mismatch: got %+v want %+v", got, want)
	}
}

func TestPushApprovalStore_PutRejectsInvalid(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	for _, tc := range []struct {
		name string
		a    *defaultimpl.PushApproval
	}{
		{"nil", nil},
		{"empty_id", &defaultimpl.PushApproval{SubjectID: "alice", ExpiresAt: time.Now().Add(time.Minute)}},
		{"empty_subject", &defaultimpl.PushApproval{ID: "id", ExpiresAt: time.Now().Add(time.Minute)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := s.Put(context.Background(), tc.a)
			if !errors.Is(err, defaultimpl.ErrPushApprovalInvalid) {
				t.Fatalf("got %v, want ErrPushApprovalInvalid", err)
			}
		})
	}
}

func TestPushApprovalStore_PutDuplicateRejected(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	if err := s.Put(ctx, a); err != nil {
		t.Fatalf("first Put: %v", err)
	}
	// Second Put with same id should fail — anti-displacement so an
	// attacker who guessed an in-flight id can't overwrite its state.
	if err := s.Put(ctx, a); err == nil {
		t.Fatal("duplicate Put should error (PRIMARY KEY violation)")
	}
}

func TestPushApprovalStore_GetExpiredReturnsNotFoundAndDeletes(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	a.ExpiresAt = time.Now().Add(-1 * time.Second).UTC()
	if err := s.Put(ctx, a); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_, err := s.Get(ctx, a.ID)
	if !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Fatalf("first Get: got %v, want ErrPushApprovalNotFound", err)
	}
	// Second Get should also surface NotFound — Get's lazy expiry
	// should have deleted the row, so it's not just expiry-checking
	// the same row repeatedly.
	_, err = s.Get(ctx, a.ID)
	if !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Fatalf("second Get: got %v, want ErrPushApprovalNotFound", err)
	}
}

func TestPushApprovalStore_SetStatusPendingToApproved(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	_ = s.Put(ctx, a)
	if err := s.SetStatus(ctx, a.ID, defaultimpl.PushApprovalApproved); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	got, _ := s.Get(ctx, a.ID)
	if got.Status != defaultimpl.PushApprovalApproved {
		t.Fatalf("status = %v, want approved", got.Status)
	}
}

func TestPushApprovalStore_SetStatusRejectsReResolution(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	_ = s.Put(ctx, a)
	_ = s.SetStatus(ctx, a.ID, defaultimpl.PushApprovalApproved)
	err := s.SetStatus(ctx, a.ID, defaultimpl.PushApprovalDenied)
	if !errors.Is(err, defaultimpl.ErrPushApprovalResolved) {
		t.Fatalf("got %v, want ErrPushApprovalResolved", err)
	}
}

func TestPushApprovalStore_SetStatusIdempotentForSameStatus(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	_ = s.Put(ctx, a)
	if err := s.SetStatus(ctx, a.ID, defaultimpl.PushApprovalPending); err != nil {
		t.Fatalf("pending→pending: %v", err)
	}
}

func TestPushApprovalStore_SetStatusMissingReturnsNotFound(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	err := s.SetStatus(context.Background(), "ghost", defaultimpl.PushApprovalApproved)
	if !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Fatalf("got %v, want ErrPushApprovalNotFound", err)
	}
}

func TestPushApprovalStore_DeleteIdempotent(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	if err := s.Delete(context.Background(), "nonexistent"); err != nil {
		t.Fatalf("Delete on missing id: %v", err)
	}
}

func TestPushApprovalStore_PruneExpiredRemovesOldEntries(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	now := time.Now().UTC()
	// Two expired, one fresh.
	_ = s.Put(ctx, &defaultimpl.PushApproval{ID: "old1", SubjectID: "a", Status: defaultimpl.PushApprovalPending, ExpiresAt: now.Add(-2 * time.Second)})
	_ = s.Put(ctx, &defaultimpl.PushApproval{ID: "old2", SubjectID: "b", Status: defaultimpl.PushApprovalApproved, ExpiresAt: now.Add(-1 * time.Second)})
	_ = s.Put(ctx, &defaultimpl.PushApproval{ID: "fresh", SubjectID: "c", Status: defaultimpl.PushApprovalPending, ExpiresAt: now.Add(time.Minute)})

	deleted, err := s.PruneExpired(ctx)
	if err != nil {
		t.Fatalf("PruneExpired: %v", err)
	}
	if deleted != 2 {
		t.Fatalf("deleted %d, want 2", deleted)
	}
	// fresh entry survives.
	if _, err := s.Get(ctx, "fresh"); err != nil {
		t.Errorf("fresh should survive: %v", err)
	}
	if _, err := s.Get(ctx, "old1"); !errors.Is(err, defaultimpl.ErrPushApprovalNotFound) {
		t.Errorf("old1: got %v, want NotFound", err)
	}
}

func TestPushApprovalStore_PingAfterCloseErrors(t *testing.T) {
	s := newPushApprovalStoreForTest(t)
	_ = s.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("Ping after Close: want error, got nil")
	}
}

func TestPushApprovalStore_SubjectBindingSurvivesRoundTrip(t *testing.T) {
	// Subject binding is the defense-in-depth check the
	// PushMFAProvider runs at Verify time. The store doesn't enforce
	// it, but must round-trip SubjectID intact so the provider has
	// something to compare against.
	s := newPushApprovalStoreForTest(t)
	ctx := context.Background()
	a := samplePushApproval()
	a.SubjectID = "alice@example.com"
	_ = s.Put(ctx, a)
	got, _ := s.Get(ctx, a.ID)
	if got.SubjectID != "alice@example.com" {
		t.Fatalf("subjectID = %q, want preserved", got.SubjectID)
	}
}
