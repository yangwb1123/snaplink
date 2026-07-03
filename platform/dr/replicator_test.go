package dr

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// fixedExport returns an ExportFunc that always produces the same
// snap_-prefixed name + payload — enough for the copy/verify path tests
// that don't care about retention ordering.
func fixedExport(name string, data []byte) ExportFunc {
	return func(context.Context) (string, []byte, error) {
		return name, data, nil
	}
}

func TestNewSnapshotReplicator_Validation(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewSnapshotReplicator(nil, dir, 0, 0, nil); err == nil {
		t.Fatal("expected error for nil export func")
	}
	if _, err := NewSnapshotReplicator(fixedExport("snap_x", nil), "", 0, 0, nil); err == nil {
		t.Fatal("expected error for empty target dir")
	}
	r, err := NewSnapshotReplicator(fixedExport("snap_x", nil), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if r.Interval != DefaultReplicationInterval {
		t.Errorf("Interval = %v, want default %v", r.Interval, DefaultReplicationInterval)
	}
	if r.Keep != DefaultReplicationKeep {
		t.Errorf("Keep = %v, want default %v", r.Keep, DefaultReplicationKeep)
	}
}

func TestSnapshotReplicator_ReplicateOnce_CopiesAndVerifies(t *testing.T) {
	dir := t.TempDir()
	payload := []byte(`{"envelope_version":"1","body":"c2VhbGVk"}`)
	r, err := NewSnapshotReplicator(fixedExport("snap_2026-01-01T00-00-00Z_AAAAAA", payload), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	if err := r.ReplicateOnce(context.Background()); err != nil {
		t.Fatalf("ReplicateOnce: %v", err)
	}

	// The replica landed under TargetDir with the .snap extension and
	// byte-identical content — this IS the checksum-verified copy path
	// (copyVerified reads the file back and compares SHA-256 before the
	// rename that makes it visible).
	want := filepath.Join(dir, "snap_2026-01-01T00-00-00Z_AAAAAA.snap")
	got, err := os.ReadFile(want)
	if err != nil {
		t.Fatalf("replica file missing: %v", err)
	}
	if string(got) != string(payload) {
		t.Errorf("replica content = %q, want %q", got, payload)
	}
	sum := sha256.Sum256(got)
	wantSum := sha256.Sum256(payload)
	if sum != wantSum {
		t.Errorf("checksum mismatch: got %x want %x", sum, wantSum)
	}

	ts, ok := r.LastSuccess()
	if !ok || ts.IsZero() {
		t.Error("LastSuccess() should report the completed cycle")
	}
	if e := r.LastError(); e != "" {
		t.Errorf("LastError() = %q, want empty after success", e)
	}

	// No stray temp files left behind after the rename.
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() != "snap_2026-01-01T00-00-00Z_AAAAAA.snap" {
			t.Errorf("unexpected leftover file %q in target dir", e.Name())
		}
	}
}

func TestSnapshotReplicator_RetentionKeepsNewestN(t *testing.T) {
	dir := t.TempDir()
	const total, keep = 5, 2
	seq := 0
	export := func(context.Context) (string, []byte, error) {
		seq++
		// Fixed-width zero-padded sequence keeps lexicographic order equal
		// to chronological order, exactly like the real snap_<utc-stamp>
		// convention pruneReplicas relies on.
		return fmt.Sprintf("snap_%04d", seq), []byte(fmt.Sprintf("payload-%d", seq)), nil
	}
	r, err := NewSnapshotReplicator(export, dir, 0, keep, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	for i := 0; i < total; i++ {
		if err := r.ReplicateOnce(context.Background()); err != nil {
			t.Fatalf("ReplicateOnce[%d]: %v", i, err)
		}
	}

	inv, err := r.Inventory()
	if err != nil {
		t.Fatalf("Inventory: %v", err)
	}
	if len(inv) != keep {
		t.Fatalf("retained %d replicas, want %d", len(inv), keep)
	}
	// Oldest-first; the survivors must be the LAST `keep` exports.
	wantNames := []string{fmt.Sprintf("snap_%04d.snap", total-1), fmt.Sprintf("snap_%04d.snap", total)}
	for i, w := range wantNames {
		if inv[i].Name != w {
			t.Errorf("inventory[%d].Name = %q, want %q", i, inv[i].Name, w)
		}
	}
}

func TestSnapshotReplicator_ExportError_RecordsLastError(t *testing.T) {
	dir := t.TempDir()
	wantErr := errors.New("boom")
	r, err := NewSnapshotReplicator(func(context.Context) (string, []byte, error) {
		return "", nil, wantErr
	}, dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	if err := r.ReplicateOnce(context.Background()); err == nil {
		t.Fatal("expected ReplicateOnce to fail")
	}
	if _, ok := r.LastSuccess(); ok {
		t.Error("LastSuccess() should stay unset after an export failure")
	}
	if e := r.LastError(); e == "" {
		t.Error("LastError() should be populated after a failed cycle")
	}
}

func TestSnapshotReplicator_ReplicaFileName_RejectsUnsafeNames(t *testing.T) {
	cases := []struct {
		name    string
		wantErr bool
	}{
		{"snap_ok", false},
		{"snap_ok.snap", false},
		{"", true},
		{"../escape", true},
		{"snap_../escape", true},
		{"nofix_1234", true}, // missing the snap_ prefix pruning relies on
	}
	for _, c := range cases {
		_, err := replicaFileName(c.name)
		if (err != nil) != c.wantErr {
			t.Errorf("replicaFileName(%q) error = %v, wantErr %v", c.name, err, c.wantErr)
		}
	}
}

func TestSnapshotReplicator_Run_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	r, err := NewSnapshotReplicator(fixedExport("snap_run", []byte("x")), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := r.Run(ctx)
	cancel()
	<-done // must close promptly; a hang here fails the test via `go test` timeout.

	if _, ok := r.LastSuccess(); !ok {
		t.Error("Run should fire an immediate first cycle before waiting on the ticker")
	}
}

func TestSnapshotReplicator_Inventory_MissingDirIsEmptyNotError(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	r, err := NewSnapshotReplicator(fixedExport("snap_x", []byte("x")), dir, 0, 0, nil)
	if err != nil {
		t.Fatalf("NewSnapshotReplicator: %v", err)
	}
	inv, err := r.Inventory()
	if err != nil {
		t.Fatalf("Inventory on missing dir should not error, got %v", err)
	}
	if len(inv) != 0 {
		t.Errorf("Inventory on missing dir = %v, want empty", inv)
	}
}
