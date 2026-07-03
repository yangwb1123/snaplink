package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/snaplink/sso/cmd/sso-server/serverbuildstore"
	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/platform/metrics"
)

// TestWireDR_DisabledReturnsNil — the byte-identical-when-off contract every
// optional subsystem in this binary follows (see wireSnapshotReleases,
// wireDR's own doc comment).
func TestWireDR_DisabledReturnsNil(t *testing.T) {
	t.Parallel()
	b := &appBuilder{cfg: &config.Config{}, logger: quietLogger()}
	dw, err := b.wireDR(&snapshotReleaseWiring{})
	if err != nil || dw != nil {
		t.Fatalf("wireDR() = (%v, %v), want (nil, nil) when dr.enabled=false", dw, err)
	}
}

// TestWireDR_RequiresSnapshotSubsystem — DR replicates the snapshot
// pipeline's export; enabling it without snapshot.enabled=true must fail
// loud at boot rather than silently doing nothing.
func TestWireDR_RequiresSnapshotSubsystem(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.DR.Enabled = true
	cfg.DR.TargetDir = t.TempDir()
	b := &appBuilder{cfg: cfg, logger: quietLogger()}
	if _, err := b.wireDR(&snapshotReleaseWiring{}); err == nil {
		t.Fatal("expected error when dr.enabled without a wired snapshot subsystem")
	}
}

// TestWireDR_HappyPath_ReplicatesToTargetDir wires a real (inline-backed)
// snapshot pipeline + a bare Snapshotter, enables DR, and confirms the
// background loop's immediate first cycle lands a verified replica in the
// configured target dir.
func TestWireDR_HappyPath_ReplicatesToTargetDir(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Snapshot.Enabled = true
	cfg.Snapshot.Storage.Backend = "inline"
	pipe, store, err := serverbuildstore.BuildSnapshotSubsystem(cfg, quietLogger())
	if err != nil {
		t.Fatalf("BuildSnapshotSubsystem: %v", err)
	}

	targetDir := t.TempDir()
	cfg.DR.Enabled = true
	cfg.DR.TargetDir = targetDir
	cfg.DR.RPOTarget = time.Hour

	b := &appBuilder{cfg: cfg, logger: quietLogger(), metricsRegistry: metrics.New()}
	srw := &snapshotReleaseWiring{
		pipeline: pipe, storage: store,
		snapshotter: &snapshot.Snapshotter{Namespace: "test"},
	}
	dw, err := b.wireDR(srw)
	if err != nil {
		t.Fatalf("wireDR: %v", err)
	}
	if dw == nil || dw.readiness == nil || dw.cancel == nil || dw.done == nil {
		t.Fatalf("wireDR() = %+v, want a fully populated drWiring", dw)
	}
	t.Cleanup(func() {
		dw.cancel()
		<-dw.done
	})

	// Run's immediate first cycle happens on its own goroutine (see
	// SnapshotReplicator.Run); give it a moment to land before asserting —
	// same idiom as the audit/push retention loop tests in this package.
	deadline := time.Now().Add(2 * time.Second)
	var completed bool
	for time.Now().Before(deadline) {
		if _, ok := dw.readiness.Replicator.LastSuccess(); ok {
			completed = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !completed {
		t.Fatal("DR replicator never completed its first cycle within the deadline")
	}
	if ready, _, reason := dw.readiness.Evaluate(); !ready {
		t.Errorf("readiness not ready after first cycle: %s", reason)
	}

	entries, err := os.ReadDir(targetDir)
	if err != nil {
		t.Fatalf("ReadDir(targetDir): %v", err)
	}
	found := false
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".snap" {
			found = true
		}
	}
	if !found {
		t.Errorf("no .snap replica found in %s, entries: %v", targetDir, entries)
	}
}
