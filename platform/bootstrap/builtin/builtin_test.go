package builtin_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	storagefile "github.com/yangwb1123/snaplink/interfaces/snapshot/storagefile"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/bootstrap/builtin"
	"github.com/yangwb1123/snaplink/platform/bootstrap/memory"
)

// stageSnapshot exports a Snapshot from src* into a tempdir-backed file
// Storage and returns the file:// URI to feed into ApplyRestore. The
// snapshot is stamped with bootstrapState.AppliedVersion=highVersion so
// AdvanceBootstrap has something to bump to.
func stageSnapshot(t *testing.T, srcClients sso.ClientStore, srcUsers sso.UserProvider, ns string, highVersion int) string {
	t.Helper()
	dir := t.TempDir()
	st, err := storagefile.New(dir)
	if err != nil {
		t.Fatalf("file storage: %v", err)
	}
	tracker := memory.New()
	if highVersion > 0 {
		_ = tracker.MarkApplied(context.Background(), ns, highVersion, "test")
	}
	snapper := &snapshot.Snapshotter{
		Clients:   srcClients,
		Users:     srcUsers,
		Tracker:   tracker,
		Namespace: ns,
	}
	snap, err := snapper.Export(context.Background(), snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	pipeline := &snapshot.Pipeline{}
	if err := pipeline.Save(context.Background(), snap, st, snap.SnapshotID); err != nil {
		t.Fatalf("pipeline save: %v", err)
	}
	return "file://" + filepath.Join(dir, snap.SnapshotID+".snap")
}

func TestApplyRestore_NilPlanIsNoop(t *testing.T) {
	t.Parallel()
	rep, err := builtin.ApplyRestore(context.Background(), nil)
	if err != nil || rep != nil {
		t.Fatalf("nil plan: got rep=%v err=%v", rep, err)
	}
}

func TestApplyRestore_EmptyURIIsNoop(t *testing.T) {
	t.Parallel()
	rep, err := builtin.ApplyRestore(context.Background(), &builtin.RestorePlan{})
	if err != nil || rep != nil {
		t.Fatalf("empty URI: got rep=%v err=%v", rep, err)
	}
}

func TestApplyRestore_RoundTripAdvancesBootstrap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const ns = "sso-server"

	// Source side — the "donor" node.
	srcClients := defaultimpl.NewMemoryClientStore()
	srcClients.AddSeed(&sso.Client{ID: "web-app", Name: "Web", Active: true})
	srcUsers := defaultimpl.NewMemoryUserProvider()
	_ = srcUsers.CreateOrUpdate(ctx, &sso.User{ID: "alice", Provider: "password"})
	const sourceVersion = 4
	uri := stageSnapshot(t, srcClients, srcUsers, ns, sourceVersion)

	// Destination side — the "recipient" node.
	dstClients := defaultimpl.NewMemoryClientStore()
	dstUsers := defaultimpl.NewMemoryUserProvider()
	dstTracker := memory.New()
	restorer := &snapshot.Restorer{
		Clients:   dstClients,
		Users:     dstUsers,
		Tracker:   dstTracker,
		Namespace: ns,
	}

	plan := &builtin.RestorePlan{
		URI:      uri,
		Pipeline: &snapshot.Pipeline{},
		Restorer: restorer,
	}
	rep, err := builtin.ApplyRestore(ctx, plan)
	if err != nil {
		t.Fatalf("ApplyRestore: %v", err)
	}
	if rep == nil {
		t.Fatal("nil report")
	}

	// Resources moved.
	if _, err := dstClients.Get(ctx, "web-app"); err != nil {
		t.Errorf("client missing: %v", err)
	}
	if _, err := dstUsers.GetByID(ctx, "alice"); err != nil {
		t.Errorf("user missing: %v", err)
	}

	// Tracker bumped to source's recorded version.
	got, err := dstTracker.AppliedVersion(ctx, ns)
	if err != nil {
		t.Fatalf("AppliedVersion: %v", err)
	}
	if got != sourceVersion {
		t.Errorf("tracker = %d, want %d", got, sourceVersion)
	}

	// Subsequent runner.Run() should skip every step whose Version <=
	// sourceVersion. Sanity-check by registering a fake step at v=2.
	var ran bool
	r := bootstrap.NewRunner(ns, dstTracker)
	r.Register(bootstrap.StepFunc("would_run_normally", 2, func(_ context.Context) error {
		ran = true
		return nil
	}))
	if err := r.Run(ctx); err != nil {
		t.Fatalf("runner.Run: %v", err)
	}
	if ran {
		t.Errorf("step at v=2 ran despite tracker=%d", got)
	}

	// And a step at v=sourceVersion+1 SHOULD run.
	var laterRan bool
	r2 := bootstrap.NewRunner(ns, dstTracker)
	r2.Register(bootstrap.StepFunc("after_snapshot", sourceVersion+1, func(_ context.Context) error {
		laterRan = true
		return nil
	}))
	if err := r2.Run(ctx); err != nil {
		t.Fatalf("runner2.Run: %v", err)
	}
	if !laterRan {
		t.Errorf("step at v=%d did not run", sourceVersion+1)
	}
}

func TestApplyRestore_MissingPipelineIsError(t *testing.T) {
	t.Parallel()
	_, err := builtin.ApplyRestore(context.Background(), &builtin.RestorePlan{URI: "file:///nope.snap"})
	if err == nil {
		t.Fatal("expected error for missing Pipeline/Restorer")
	}
}

func TestApplyRestore_BadURISurfacesError(t *testing.T) {
	t.Parallel()
	_, err := builtin.ApplyRestore(context.Background(), &builtin.RestorePlan{
		URI:      "s3://nope",
		Pipeline: &snapshot.Pipeline{},
		Restorer: &snapshot.Restorer{},
	})
	if err == nil {
		t.Fatal("expected error for unsupported scheme")
	}
}
