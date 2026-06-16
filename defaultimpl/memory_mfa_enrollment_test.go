package defaultimpl_test

import (
	"context"
	"testing"
	"time"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/defaultimpl"
)

func TestMemoryMFAEnrollmentStore_AddListRemove(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAEnrollmentStore()

	s.AddFactor("alice", core.MFAEnrolledFactor{ID: "f1", Method: "totp", Label: "Authy", AddedAt: time.Now()})
	s.AddFactor("alice", core.MFAEnrolledFactor{ID: "f2", Method: "webauthn", Label: "Passkey"})
	s.AddFactor("bob", core.MFAEnrolledFactor{ID: "f3", Method: "totp"})

	alice, err := s.ListFactors(ctx, "alice")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(alice) != 2 {
		t.Fatalf("alice factors = %d, want 2", len(alice))
	}

	// Returned slice must be a copy — mutating it must not corrupt the store.
	alice[0].Label = "MUTATED"
	again, _ := s.ListFactors(ctx, "alice")
	if again[0].Label == "MUTATED" {
		t.Error("ListFactors leaked the backing array")
	}

	// Remove one factor.
	if err := s.RemoveFactor(ctx, "alice", "f1"); err != nil {
		t.Fatalf("RemoveFactor: %v", err)
	}
	after, _ := s.ListFactors(ctx, "alice")
	if len(after) != 1 || after[0].ID != "f2" {
		t.Errorf("after remove = %+v", after)
	}

	// Removing a non-existent factor is idempotent.
	if err := s.RemoveFactor(ctx, "alice", "ghost"); err != nil {
		t.Errorf("RemoveFactor(ghost) = %v", err)
	}

	// Removing the last factor drops the user key (no empty slice lingering).
	if err := s.RemoveFactor(ctx, "alice", "f2"); err != nil {
		t.Fatalf("RemoveFactor(last): %v", err)
	}
	empty, _ := s.ListFactors(ctx, "alice")
	if len(empty) != 0 {
		t.Errorf("alice should have no factors, got %+v", empty)
	}

	// Bob is untouched.
	bob, _ := s.ListFactors(ctx, "bob")
	if len(bob) != 1 {
		t.Errorf("bob factors = %d, want 1", len(bob))
	}
}

func TestMemoryMFAEnrollmentStore_ListUnknownUser(t *testing.T) {
	ctx := context.Background()
	s := defaultimpl.NewMemoryMFAEnrollmentStore()
	got, err := s.ListFactors(ctx, "nobody")
	if err != nil {
		t.Fatalf("ListFactors: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("unknown user factors = %+v, want empty", got)
	}
	// Remove on an unknown user is a no-op.
	if err := s.RemoveFactor(ctx, "nobody", "f"); err != nil {
		t.Errorf("RemoveFactor(unknown user) = %v", err)
	}
}
