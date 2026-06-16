package security_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/security"
)

// MemoryPairwiseSubjectStore round-trips pairwise→local mappings.
// LocalSubject on an unmapped sub MUST return ErrPairwiseUnknown so
// resource handlers reject it with the same wire shape as any unknown
// token (oracle resistance).

func TestMemoryPairwiseSubjectStore_RoundTrip(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := security.NewMemoryPairwiseSubjectStore()

	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("MapPairwise: %v", err)
	}
	local, err := s.LocalSubject(ctx, "opaque-1")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "alice" {
		t.Errorf("LocalSubject = %q, want alice", local)
	}
}

func TestMemoryPairwiseSubjectStore_IdempotentUpsert(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := security.NewMemoryPairwiseSubjectStore()

	// Two identical maps for the same pair must both succeed (issuance
	// runs MapPairwise on every login, not just the first).
	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("first MapPairwise: %v", err)
	}
	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("repeat MapPairwise: %v", err)
	}
	// Re-mapping to a different local subject overwrites.
	if err := s.MapPairwise(ctx, "opaque-1", "bob"); err != nil {
		t.Fatalf("overwrite MapPairwise: %v", err)
	}
	local, err := s.LocalSubject(ctx, "opaque-1")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "bob" {
		t.Errorf("LocalSubject after overwrite = %q, want bob", local)
	}
}

func TestMemoryPairwiseSubjectStore_UnknownReturnsSentinel(t *testing.T) {
	t.Parallel()
	s := security.NewMemoryPairwiseSubjectStore()
	_, err := s.LocalSubject(context.Background(), "never-mapped")
	if !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Errorf("LocalSubject(unknown) err = %v, want ErrPairwiseUnknown", err)
	}
}

func TestMemoryPairwiseSubjectStore_RejectsEmpty(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s := security.NewMemoryPairwiseSubjectStore()
	if err := s.MapPairwise(ctx, "", "alice"); err == nil {
		t.Error("MapPairwise with empty pairwise sub accepted")
	}
	if err := s.MapPairwise(ctx, "opaque-1", ""); err == nil {
		t.Error("MapPairwise with empty local sub accepted")
	}
}
