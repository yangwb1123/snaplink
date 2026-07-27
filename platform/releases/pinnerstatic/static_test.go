package static_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/platform/releases/pinnerstatic"
)

// stagedBundle materialises a fake bundle directory inside dir so the
// Pinner has something to point its symlink at.
func stagedBundle(t *testing.T, dir, id string) {
	t.Helper()
	bundle := filepath.Join(dir, id)
	if err := os.MkdirAll(bundle, 0o700); err != nil {
		t.Fatalf("mkdir bundle: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bundle, "index.html"), []byte("<html>"+id+"</html>"), 0o600); err != nil {
		t.Fatalf("write bundle file: %v", err)
	}
}

func TestNew_RejectsMissingDir(t *testing.T) {
	t.Parallel()
	if _, err := static.New(filepath.Join(t.TempDir(), "does-not-exist")); err == nil {
		t.Fatal("expected error for missing dir")
	}
}

func TestNew_RejectsEmptyDir(t *testing.T) {
	t.Parallel()
	if _, err := static.New(""); err == nil {
		t.Fatal("expected error for empty dir")
	}
}

func TestPinForward_SwapsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stagedBundle(t, dir, "rel-1")
	p, err := static.New(dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := p.PinForward(context.Background(), &releases.Release{ID: "rel-1"}); err != nil {
		t.Fatalf("PinForward: %v", err)
	}
	got, err := os.Readlink(filepath.Join(dir, static.CurrentSymlink))
	if err != nil {
		t.Fatalf("Readlink: %v", err)
	}
	if got != "rel-1" {
		t.Errorf("symlink target=%q want rel-1", got)
	}
}

func TestPinForward_OverwritesPreviousSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stagedBundle(t, dir, "rel-1")
	stagedBundle(t, dir, "rel-2")
	p, _ := static.New(dir)
	ctx := context.Background()
	if err := p.PinForward(ctx, &releases.Release{ID: "rel-1"}); err != nil {
		t.Fatalf("first PinForward: %v", err)
	}
	if err := p.PinForward(ctx, &releases.Release{ID: "rel-2"}); err != nil {
		t.Fatalf("second PinForward: %v", err)
	}
	got, _ := os.Readlink(filepath.Join(dir, static.CurrentSymlink))
	if got != "rel-2" {
		t.Errorf("after second pin: target=%q want rel-2", got)
	}
}

func TestPinRollback_SwapsSymlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	stagedBundle(t, dir, "rel-1")
	stagedBundle(t, dir, "rel-2")
	p, _ := static.New(dir)
	ctx := context.Background()
	_ = p.PinForward(ctx, &releases.Release{ID: "rel-2"})
	if err := p.PinRollback(ctx, &releases.Release{ID: "rel-1"}); err != nil {
		t.Fatalf("PinRollback: %v", err)
	}
	got, _ := os.Readlink(filepath.Join(dir, static.CurrentSymlink))
	if got != "rel-1" {
		t.Errorf("after rollback: target=%q want rel-1", got)
	}
}

func TestPinForward_BundleMissingIsError(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	p, _ := static.New(dir)
	err := p.PinForward(context.Background(), &releases.Release{ID: "rel-missing"})
	if err == nil {
		t.Fatal("expected error for missing bundle dir")
	}
}
