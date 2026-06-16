package snapshot_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/bootstrap/memory"
	"github.com/snaplink/sso/defaultimpl"
	netmemory "github.com/snaplink/sso/netpolicy/memory"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/snapshot"
)

// TestAdvanceBootstrap_NoTracker proves AdvanceBootstrap is a graceful no-op
// (Attempted=true, NoOp=true, reason explains why) when no Tracker is wired.
func TestAdvanceBootstrap_NoTracker(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	// Restorer with everything EXCEPT a Tracker.
	r := &snapshot.Restorer{
		Clients:     defaultimpl.NewMemoryClientStore(),
		Users:       defaultimpl.NewMemoryUserProvider(),
		Permissions: permissions.NewMemoryProvider(),
		NetPolicy:   netmemory.New(),
		Namespace:   "sso-server",
		// Tracker intentionally nil.
	}
	rep, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !rep.Bootstrap.Attempted {
		t.Errorf("Bootstrap.Attempted=false, want true")
	}
	if !rep.Bootstrap.NoOp {
		t.Errorf("Bootstrap.NoOp=false, want true (no tracker)")
	}
	if rep.Bootstrap.Reason == "" {
		t.Errorf("Bootstrap.Reason empty, want explanation")
	}
}

// TestAdvanceBootstrap_NotNewer proves advance is a no-op when the
// destination tracker is already at or beyond the snapshot's version.
func TestAdvanceBootstrap_NotNewer(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t) // snapshot version = 2
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	// Push the destination ahead of the snapshot.
	if err := dst.tracker.MarkApplied(ctx, "sso-server", 5, "preseed"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if !rep.Bootstrap.NoOp {
		t.Errorf("expected NoOp when dst (5) >= snapshot (2): %+v", rep.Bootstrap)
	}
	if rep.Bootstrap.From != 5 || rep.Bootstrap.To != 2 {
		t.Errorf("From/To = %d/%d, want 5/2", rep.Bootstrap.From, rep.Bootstrap.To)
	}
	// Tracker must NOT have moved backward.
	v, _ := dst.tracker.AppliedVersion(ctx, "sso-server")
	if v != 5 {
		t.Errorf("tracker regressed to %d, want 5", v)
	}
}

// TestAdvanceBootstrap_Advances proves the happy path bumps the destination
// tracker to the snapshot version when the snapshot is newer.
func TestAdvanceBootstrap_Advances(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t) // snapshot version = 2
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	if err := dst.tracker.MarkApplied(ctx, "sso-server", 1, "preseed"); err != nil {
		t.Fatalf("mark: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Bootstrap.NoOp {
		t.Errorf("unexpected NoOp: %+v", rep.Bootstrap)
	}
	if rep.Bootstrap.From != 1 || rep.Bootstrap.To != 2 {
		t.Errorf("From/To = %d/%d, want 1/2", rep.Bootstrap.From, rep.Bootstrap.To)
	}
	v, _ := dst.tracker.AppliedVersion(ctx, "sso-server")
	if v != 2 {
		t.Errorf("tracker = %d after advance, want 2", v)
	}
}

// TestAdvanceBootstrap_FallsBackToSnapshotNamespace proves that when the
// Restorer has no explicit Namespace it uses the snapshot's recorded one.
func TestAdvanceBootstrap_FallsBackToSnapshotNamespace(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t) // namespace "sso-server", version 2
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	tr := memory.New()
	r := &snapshot.Restorer{
		Clients: defaultimpl.NewMemoryClientStore(),
		Tracker: tr,
		// Namespace intentionally empty → must fall back to snapshot's.
	}
	rep, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Bootstrap.To != 2 {
		t.Errorf("Bootstrap.To = %d, want 2 (from snapshot namespace)", rep.Bootstrap.To)
	}
	v, _ := tr.AppliedVersion(ctx, "sso-server")
	if v != 2 {
		t.Errorf("tracker version = %d, want 2", v)
	}
}

// TestAdvanceBootstrap_DryRun proves dry-run computes From/To but does not
// move the tracker.
func TestAdvanceBootstrap_DryRun(t *testing.T) {
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeMerge, AdvanceBootstrap: true, DryRun: true,
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Bootstrap.To != 2 || rep.Bootstrap.From != 0 {
		t.Errorf("dry-run From/To = %d/%d, want 0/2", rep.Bootstrap.From, rep.Bootstrap.To)
	}
	v, _ := dst.tracker.AppliedVersion(ctx, "sso-server")
	if v != 0 {
		t.Errorf("dry-run advanced tracker to %d, want 0", v)
	}
}
