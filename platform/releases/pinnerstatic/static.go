// Package static is a frontend-bundle Pinner. It expects bundles to
// already be staged on disk under <BundleDir>/<release-id>/ (the
// operator's CI/CD job is responsible for that), and atomically
// flips a <BundleDir>/current symlink to point at the active
// release's directory. POSIX rename(2) on a symlink is atomic, so
// in-flight HTTP requests serving from "current" never see a
// partial swap.
//
// Backend deploys are out of scope — pair this with a backend-only
// Pinner (or wrap both in a composite) when both halves of the
// release need flipping. Frontend-only environments (CDN-fronted
// SPAs, HTML bundles served by an edge proxy) commonly only need
// this side.
package static

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/yangwb1123/snaplink/platform/releases"
)

// CurrentSymlink is the file name (relative to BundleDir) that
// points at the active release's bundle directory.
const CurrentSymlink = "current"

// Pinner swaps the current frontend bundle by renaming a symlink.
type Pinner struct {
	BundleDir string // absolute path to the directory containing per-release subdirs
}

// New constructs a Pinner. The directory must exist; per-release
// subdirs are NOT created here (that's the operator's CI job).
func New(bundleDir string) (*Pinner, error) {
	if bundleDir == "" {
		return nil, errors.New("releases/pinner/static: bundleDir required")
	}
	abs, err := filepath.Abs(bundleDir)
	if err != nil {
		return nil, fmt.Errorf("releases/pinner/static: abs: %w", err)
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, fmt.Errorf("releases/pinner/static: stat: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("releases/pinner/static: %q is not a directory", abs)
	}
	return &Pinner{BundleDir: abs}, nil
}

// PinForward and PinRollback both swap the symlink. Bundle ordering
// for the static Pinner is symmetric — there's no "backend first"
// because there's no backend here.
func (p *Pinner) PinForward(_ context.Context, target *releases.Release) error {
	return p.swap(target)
}

func (p *Pinner) PinRollback(_ context.Context, target *releases.Release) error {
	return p.swap(target)
}

func (p *Pinner) swap(target *releases.Release) error {
	bundle := filepath.Join(p.BundleDir, target.ID)
	if _, err := os.Stat(bundle); err != nil {
		return fmt.Errorf("releases/pinner/static: bundle %q missing: %w", bundle, err)
	}
	link := filepath.Join(p.BundleDir, CurrentSymlink)
	tmp := link + ".new"
	// Best-effort cleanup of any stale .new from a prior aborted swap.
	_ = os.Remove(tmp)
	// Relative target so bundle moves don't break the link.
	if err := os.Symlink(target.ID, tmp); err != nil {
		return fmt.Errorf("releases/pinner/static: symlink: %w", err)
	}
	if err := os.Rename(tmp, link); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("releases/pinner/static: rename: %w", err)
	}
	return nil
}

// Compile-time interface check.
var _ releases.Pinner = (*Pinner)(nil)
