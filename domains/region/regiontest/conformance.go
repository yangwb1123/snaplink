// Package regiontest is the conformance suite for region.PolicyStore
// backends (the permissions.Provider + permissionstest.ConformanceSuite
// pattern AGENTS.md §4 mandates for storage concerns): one behavioral
// contract, exercised by every shipped backend so a future backend
// inherits it for free.
package regiontest

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/region"
)

// PolicyWriter is the write-side extension every shipped backend implements
// (Set/Delete). The conformance suite REQUIRES it — the write contract is
// part of the backend contract.
type PolicyWriter interface {
	Set(ctx context.Context, tenantID string, p region.ResidencyPolicy) error
	Delete(ctx context.Context, tenantID string) error
}

// ConformanceSuite is the behavioral contract every region.PolicyStore
// backend must satisfy. Backends return a FRESH store per call.
type ConformanceSuite struct {
	New func(t *testing.T) region.PolicyStore
}

// Run executes the full scenario matrix as subtests against fresh stores.
func (s ConformanceSuite) Run(t *testing.T) {
	t.Helper()
	if s.New == nil {
		t.Fatal("ConformanceSuite.New is nil")
	}
	t.Run("absent tenant returns zero policy", s.runAbsentTenant)
	t.Run("set then get round-trips", s.runSetGet)
	t.Run("set replaces previous policy", s.runReplace)
	t.Run("delete returns to zero policy", s.runDelete)
	t.Run("invalid region id rejected and state unchanged", s.runInvalidRejected)
}

// newStore returns a fresh backend and its write-side contract, failing
// when the backend is read-only (every shipped backend implements
// Set/Delete; the write contract is part of the backend contract).
func (s ConformanceSuite) newStore(t *testing.T) (region.PolicyStore, PolicyWriter) {
	t.Helper()
	store := s.New(t)
	writer, ok := store.(PolicyWriter)
	if !ok {
		t.Fatal("backend does not implement the write-side contract (Set/Delete)")
	}
	return store, writer
}

func (s ConformanceSuite) runAbsentTenant(t *testing.T) {
	store := s.New(t)
	p, err := store.GetPolicy(context.Background(), "no-such-tenant")
	if err != nil {
		t.Fatalf("GetPolicy(absent) = %v, want nil error", err)
	}
	if !p.IsZero() {
		t.Errorf("absent tenant policy = %+v, want zero (unconstrained)", p)
	}
}
func (s ConformanceSuite) runSetGet(t *testing.T) {
	store, writer := s.newStore(t)
	want := region.ResidencyPolicy{
		HomeRegion:     "eu-west-1",
		AllowedRegions: []region.ID{"eu-west-1", "eu-central-1"},
		EnforceWrites:  true,
	}
	if err := writer.Set(context.Background(), "t1", want); err != nil {
		t.Fatalf("Set: %v", err)
	}
	got, err := store.GetPolicy(context.Background(), "t1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.HomeRegion != want.HomeRegion || !got.EnforceWrites {
		t.Errorf("round-trip mismatch: %+v vs %+v", got, want)
	}
	if len(got.AllowedRegions) != 2 || got.AllowedRegions[0] != "eu-west-1" || got.AllowedRegions[1] != "eu-central-1" {
		t.Errorf("allowed_regions mismatch: %v vs %v", got.AllowedRegions, want.AllowedRegions)
	}
}

func (s ConformanceSuite) runReplace(t *testing.T) {
	store, writer := s.newStore(t)
	_ = writer.Set(context.Background(), "t1", region.ResidencyPolicy{HomeRegion: "us-east-1"})
	if err := writer.Set(context.Background(), "t1", region.ResidencyPolicy{HomeRegion: "eu-west-1", EnforceWrites: true}); err != nil {
		t.Fatalf("second Set: %v", err)
	}
	got, err := store.GetPolicy(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.HomeRegion != "eu-west-1" || !got.EnforceWrites {
		t.Errorf("replace mismatch: %+v", got)
	}
}

func (s ConformanceSuite) runDelete(t *testing.T) {
	store, writer := s.newStore(t)
	_ = writer.Set(context.Background(), "t1", region.ResidencyPolicy{HomeRegion: "us-east-1"})
	if err := writer.Delete(context.Background(), "t1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	got, err := store.GetPolicy(context.Background(), "t1")
	if err != nil || !got.IsZero() {
		t.Errorf("post-delete = %+v, %v; want zero policy", got, err)
	}
}

func (s ConformanceSuite) runInvalidRejected(t *testing.T) {
	store, writer := s.newStore(t)
	_ = writer.Set(context.Background(), "t1", region.ResidencyPolicy{HomeRegion: "us-east-1"})
	err := writer.Set(context.Background(), "t1", region.ResidencyPolicy{
		HomeRegion:     "us-east-1",
		AllowedRegions: []region.ID{"EU-WEST-1"}, // uppercase: invalid
	})
	if !errors.Is(err, region.ErrInvalidRegion) {
		t.Fatalf("Set(invalid) = %v, want ErrInvalidRegion", err)
	}
	got, err := store.GetPolicy(context.Background(), "t1")
	if err != nil {
		t.Fatal(err)
	}
	if got.HomeRegion != "us-east-1" || len(got.AllowedRegions) != 0 {
		t.Errorf("invalid Set mutated stored state: %+v", got)
	}
}
