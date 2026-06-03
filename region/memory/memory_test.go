package memory_test

import (
	"context"
	"sync"
	"testing"

	"github.com/snaplink/sso/region"
	"github.com/snaplink/sso/region/memory"
)

func TestSetGetPolicy_Roundtrip(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	want := region.ResidencyPolicy{
		HomeRegion:     "eu-west-1",
		AllowedRegions: []region.ID{"eu-west-1", "eu-central-1"},
		EnforceWrites:  true,
	}
	s.Set("t1", want)

	got, err := s.GetPolicy(ctx, "t1")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.HomeRegion != want.HomeRegion || !got.EnforceWrites {
		t.Errorf("policy mismatch: got %+v want %+v", got, want)
	}
	if len(got.AllowedRegions) != 2 || got.AllowedRegions[0] != "eu-west-1" || got.AllowedRegions[1] != "eu-central-1" {
		t.Errorf("allowed regions mismatch: %v", got.AllowedRegions)
	}
}

func TestGetPolicy_AbsentIsZeroUnconstrained(t *testing.T) {
	s := memory.New()
	got, err := s.GetPolicy(context.Background(), "ghost")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if got.HomeRegion != "" || got.AllowedRegions != nil || got.EnforceWrites {
		t.Errorf("absent tenant not zero/unconstrained: %+v", got)
	}
}

func TestDelete_RevertsToUnconstrained(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	s.Set("t1", region.ResidencyPolicy{HomeRegion: "us-east-1", EnforceWrites: true})
	s.Delete("t1")
	got, _ := s.GetPolicy(ctx, "t1")
	if got.HomeRegion != "" || got.EnforceWrites {
		t.Errorf("policy survived Delete: %+v", got)
	}
}

func TestDelete_Idempotent(t *testing.T) {
	s := memory.New()
	// Delete of an absent tenant must not panic.
	s.Delete("ghost")
}

func TestSet_IsolatesAllowedRegionsSlice(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	regions := []region.ID{"eu-west-1", "eu-central-1"}
	s.Set("t1", region.ResidencyPolicy{HomeRegion: "eu-west-1", AllowedRegions: regions})

	// Mutating the caller's slice must not reach into the stored policy.
	regions[0] = "us-east-1"
	got, _ := s.GetPolicy(ctx, "t1")
	if got.AllowedRegions[0] != "eu-west-1" {
		t.Errorf("stored policy aliased caller slice: %v", got.AllowedRegions)
	}

	// Mutating the returned slice must not reach back either.
	got.AllowedRegions[1] = "ap-south-1"
	again, _ := s.GetPolicy(ctx, "t1")
	if again.AllowedRegions[1] != "eu-central-1" {
		t.Errorf("returned slice aliased stored policy: %v", again.AllowedRegions)
	}
}

func TestConcurrentAccess_NoRace(t *testing.T) {
	s := memory.New()
	ctx := context.Background()
	s.Set("t1", region.ResidencyPolicy{HomeRegion: "eu-west-1"})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = s.GetPolicy(ctx, "t1")
		}()
		go func(i int) {
			defer wg.Done()
			id := "t" + string(rune('a'+(i%10)))
			s.Set(id, region.ResidencyPolicy{HomeRegion: region.ID("r" + id)})
		}(i)
		go func(i int) {
			defer wg.Done()
			s.Delete("t" + string(rune('a'+(i%10))))
		}(i)
	}
	wg.Wait()
}
