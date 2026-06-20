package file_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/store/file"
)

func validRelease(id string) *releases.Release {
	return &releases.Release{
		ID:       id,
		Frontend: releases.Artifact{GitRef: "v1"},
		Backend:  releases.Artifact{GitRef: "v1"},
	}
}

func newStore(t *testing.T) *file.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := file.New(dir)
	if err != nil {
		t.Fatalf("file.New: %v", err)
	}
	return s
}

func TestRegister_GetRoundTripPersistsToDisk(t *testing.T) {
	s := newStore(t)
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
	// File should exist.
	if _, err := os.Stat(filepath.Join(s.BaseDir(), "rel-1.json")); err != nil {
		t.Errorf("file missing: %v", err)
	}
}

func TestRegister_RejectsDuplicate(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.Register(ctx, validRelease("rel-1"))
	if err := s.Register(ctx, validRelease("rel-1")); !errors.Is(err, releases.ErrReleaseExists) {
		t.Fatalf("err = %v", err)
	}
}

func TestList_SortedByID(t *testing.T) {
	s := newStore(t)
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

func TestSetCurrent_AndCurrent_PersistViaCURRENTFile(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	s1, _ := file.New(dir)
	_ = s1.Register(ctx, validRelease("rel-1"))
	if err := s1.SetCurrent(ctx, "rel-1"); err != nil {
		t.Fatalf("SetCurrent: %v", err)
	}

	// Re-open the store — Current should survive process restart.
	s2, _ := file.New(dir)
	cur, err := s2.Current(ctx)
	if err != nil {
		t.Fatalf("Current: %v", err)
	}
	if cur.ID != "rel-1" {
		t.Errorf("Current id=%q", cur.ID)
	}
}

func TestDelete_RemovesFileAndClearsCurrent(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	_ = s.Register(ctx, validRelease("rel-1"))
	_ = s.SetCurrent(ctx, "rel-1")
	if err := s.Delete(ctx, "rel-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.BaseDir(), "rel-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("file lingered: %v", err)
	}
	if _, err := s.Current(ctx); !errors.Is(err, releases.ErrNoCurrent) {
		t.Errorf("Current: %v", err)
	}
}

func TestSetCurrent_UnknownReleaseIsNotFound(t *testing.T) {
	s := newStore(t)
	if err := s.SetCurrent(context.Background(), "ghost"); !errors.Is(err, releases.ErrReleaseNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestGet_MissingIsNotFound(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get(context.Background(), "ghost"); !errors.Is(err, releases.ErrReleaseNotFound) {
		t.Fatalf("err = %v", err)
	}
}

func TestSanitizedID_StoredUnderSafeName(t *testing.T) {
	s := newStore(t)
	ctx := context.Background()
	r := validRelease("rel/with:slashes")
	if err := s.Register(ctx, r); err != nil {
		t.Fatalf("Register sanitized: %v", err)
	}
	// Underlying file uses sanitized name; Get with the same input
	// should still resolve.
	if _, err := s.Get(ctx, "rel/with:slashes"); err != nil {
		t.Errorf("Get sanitized: %v", err)
	}
}
