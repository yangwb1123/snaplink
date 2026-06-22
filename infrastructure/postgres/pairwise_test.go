package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/shared/security"
)

func freshPairwiseStore(t *testing.T) *PairwiseSubjectStore {
	t.Helper()
	s, err := NewPairwiseSubjectStore(testConfig(t))
	if err != nil {
		t.Fatalf("NewPairwiseSubjectStore: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.db.ExecContext(context.Background(), "TRUNCATE pairwise_subjects"); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	return s
}

func TestPairwise_MapAndResolve(t *testing.T) {
	s := freshPairwiseStore(t)
	ctx := context.Background()

	// Unmapped → ErrPairwiseUnknown (the oracle-safe sentinel).
	if _, err := s.LocalSubject(ctx, "never-mapped"); !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Fatalf("LocalSubject(unmapped) err = %v, want ErrPairwiseUnknown", err)
	}

	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("MapPairwise: %v", err)
	}
	local, err := s.LocalSubject(ctx, "opaque-1")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "alice" {
		t.Fatalf("LocalSubject = %q, want alice", local)
	}
}

func TestPairwise_IdempotentUpsertReplacesInFull(t *testing.T) {
	s := freshPairwiseStore(t)
	ctx := context.Background()

	// The SPI contract: MapPairwise is called on every issuance, not just the
	// first, so repeating the same pair MUST succeed.
	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("first MapPairwise: %v", err)
	}
	if err := s.MapPairwise(ctx, "opaque-1", "alice"); err != nil {
		t.Fatalf("repeat MapPairwise: %v", err)
	}

	// Upsert replaces in full: re-mapping the same pairwise sub to a new local
	// overwrites via ON CONFLICT.
	if err := s.MapPairwise(ctx, "opaque-1", "bob"); err != nil {
		t.Fatalf("overwrite MapPairwise: %v", err)
	}
	local, err := s.LocalSubject(ctx, "opaque-1")
	if err != nil {
		t.Fatalf("LocalSubject: %v", err)
	}
	if local != "bob" {
		t.Fatalf("LocalSubject after overwrite = %q, want bob", local)
	}
}

func TestPairwise_DistinctSubjectsCoexist(t *testing.T) {
	s := freshPairwiseStore(t)
	ctx := context.Background()

	// Two pairwise subs (different sectors) for the same local user, plus a
	// pairwise sub for a different local user. Each resolves independently — no
	// cross-row leak.
	for ps, ls := range map[string]string{
		"sector-a-alice": "alice",
		"sector-b-alice": "alice",
		"sector-a-bob":   "bob",
	} {
		if err := s.MapPairwise(ctx, ps, ls); err != nil {
			t.Fatalf("MapPairwise(%s): %v", ps, err)
		}
	}
	for ps, want := range map[string]string{
		"sector-a-alice": "alice",
		"sector-b-alice": "alice",
		"sector-a-bob":   "bob",
	} {
		got, err := s.LocalSubject(ctx, ps)
		if err != nil {
			t.Fatalf("LocalSubject(%s): %v", ps, err)
		}
		if got != want {
			t.Fatalf("LocalSubject(%s) = %q, want %q", ps, got, want)
		}
	}
}

func TestPairwise_RejectsEmpty(t *testing.T) {
	s := freshPairwiseStore(t)
	ctx := context.Background()

	if err := s.MapPairwise(ctx, "", "alice"); err == nil {
		t.Error("MapPairwise with empty pairwise sub accepted")
	}
	if err := s.MapPairwise(ctx, "opaque-1", ""); err == nil {
		t.Error("MapPairwise with empty local sub accepted")
	}
	// Empty pairwise lookup short-circuits to the unknown sentinel, no query.
	if _, err := s.LocalSubject(ctx, ""); !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Errorf("LocalSubject(empty) err = %v, want ErrPairwiseUnknown", err)
	}
}
