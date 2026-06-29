package memory_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/storememory"
)

func validRelease(id string) *releases.Release {
	return &releases.Release{
		ID:       id,
		Frontend: releases.Artifact{GitRef: "v1"},
		Backend:  releases.Artifact{GitRef: "v1"},
	}
}

func TestRegister_GetRoundTrip(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	if err := s.Register(ctx, validRelease("rel-1")); err != nil {
		t.Fatalf("Register: %v", err)
	}
	got, err := s.Get(ctx, "rel-1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.ID != "rel-1" {
		t.Errorf("Get id=%q", got.ID)
	}
}

func TestRegister_RejectsDuplicate(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.Register(ctx, validRelease("rel-1"))
	if err := s.Register(ctx, validRelease("rel-1")); !errors.Is(err, releases.ErrReleaseExists) {
		t.Fatalf("err = %v, want ErrReleaseExists", err)
	}
}

func TestRegister_RejectsInvalid(t *testing.T) {
	t.Parallel()
	s := memory.New()
	r := &releases.Release{ID: "rel-1"} // no artifacts
	if err := s.Register(context.Background(), r); !errors.Is(err, releases.ErrInvalidPair) {
		t.Fatalf("err = %v", err)
	}
}

func TestGet_MissingReturnsNotFound(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if _, err := s.Get(context.Background(), "ghost"); !errors.Is(err, releases.ErrReleaseNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestList_SortedByID(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	for _, id := range []string{"rel-c", "rel-a", "rel-b"} {
		_ = s.Register(ctx, validRelease(id))
	}
	out, err := s.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(out) != 3 || out[0].ID != "rel-a" || out[2].ID != "rel-c" {
		t.Errorf("List = %+v", out)
	}
}

func TestSetCurrent_AndCurrent(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	if _, err := s.Current(ctx); !errors.Is(err, releases.ErrNoCurrent) {
		t.Fatalf("Current on fresh store: %v", err)
	}
	_ = s.Register(ctx, validRelease("rel-1"))
	if err := s.SetCurrent(ctx, "rel-1"); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}
	cur, err := s.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur.ID != "rel-1" {
		t.Errorf("Current id=%q", cur.ID)
	}
}

func TestSetCurrent_UnknownReleaseIsNotFound(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if err := s.SetCurrent(context.Background(), "ghost"); !errors.Is(err, releases.ErrReleaseNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestDelete_ClearsCurrentWhenSame(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.Register(ctx, validRelease("rel-1"))
	_ = s.SetCurrent(ctx, "rel-1")
	if err := s.Delete(ctx, "rel-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := s.Current(ctx); !errors.Is(err, releases.ErrNoCurrent) {
		t.Fatalf("Current after Delete: %v", err)
	}
}

func TestDelete_MissingIsIdempotent(t *testing.T) {
	t.Parallel()
	s := memory.New()
	if err := s.Delete(context.Background(), "ghost"); err != nil {
		t.Errorf("Delete missing: %v", err)
	}
}

func TestClearCurrent_KeepsReleases(t *testing.T) {
	t.Parallel()
	s := memory.New()
	ctx := context.Background()
	_ = s.Register(ctx, validRelease("rel-1"))
	_ = s.SetCurrent(ctx, "rel-1")
	if err := s.ClearCurrent(ctx); err != nil {
		t.Fatalf("ClearCurrent: %v", err)
	}
	if _, err := s.Get(ctx, "rel-1"); err != nil {
		t.Errorf("release dropped: %v", err)
	}
	if _, err := s.Current(ctx); !errors.Is(err, releases.ErrNoCurrent) {
		t.Errorf("Current: %v", err)
	}
}
