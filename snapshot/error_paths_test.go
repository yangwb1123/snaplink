package snapshot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/defaultimpl"
	"github.com/snaplink/sso/snapshot"
)

// errStorage is a boundary error-fake for the Storage persistence
// interface. There is no failing in-memory Storage impl (inline.Storage
// never errors), so this thin fake is the only way to exercise the
// documented error-handling branches in Pipeline.Save / Pipeline.Load /
// PruneOldest. It is NOT a domain mock — it stands in for an I/O fault
// (disk full, permission denied) at the persistence edge.
type errStorage struct {
	putErr    error
	getErr    error
	listErr   error
	deleteErr error
}

var errBoom = errors.New("errStorage: boom")

func (e *errStorage) Put(context.Context, string, []byte) error {
	if e.putErr != nil {
		return e.putErr
	}
	return nil
}

func (e *errStorage) Get(context.Context, string) ([]byte, error) {
	return nil, e.getErr
}

func (e *errStorage) List(context.Context) ([]string, error) {
	return nil, e.listErr
}

func (e *errStorage) Delete(context.Context, string) error {
	return e.deleteErr
}

// TestPipeline_Save_PutError surfaces a storage write fault.
func TestPipeline_Save_PutError(t *testing.T) {
	snap := &snapshot.Snapshot{SnapshotID: "x", SchemaVersion: snapshot.SchemaVersion, SourceNamespace: "ns"}
	st := &errStorage{putErr: errBoom}
	if err := (&snapshot.Pipeline{}).Save(context.Background(), snap, st, "x"); err == nil {
		t.Error("Save must propagate Put error")
	}
}

// TestPipeline_Load_GetError surfaces a storage read fault (non-sentinel).
func TestPipeline_Load_GetError(t *testing.T) {
	st := &errStorage{getErr: errBoom}
	if _, err := (&snapshot.Pipeline{}).Load(context.Background(), st, "x"); err == nil {
		t.Error("Load must propagate Get error")
	}
}

// TestPruneOldest_ListError surfaces a storage enumeration fault.
func TestPruneOldest_ListError(t *testing.T) {
	st := &errStorage{listErr: errBoom}
	if _, err := snapshot.PruneOldest(context.Background(), st, 1); err == nil {
		t.Error("PruneOldest must propagate List error")
	}
}

// TestPruneOldest_DeleteErrorContinues proves a Delete fault doesn't stop the
// loop: the helper reports the partial-success list AND the first error.
func TestPruneOldest_DeleteErrorContinues(t *testing.T) {
	st := &countingDeleteStorage{
		names:     []string{"snap_2026-01-01T00-00-00Z_a", "snap_2026-01-02T00-00-00Z_b", "snap_2026-01-03T00-00-00Z_c"},
		failOnIdx: 0, // first delete fails, the rest succeed
	}
	deleted, err := snapshot.PruneOldest(context.Background(), st, 1)
	if err == nil {
		t.Fatal("expected first-error to be reported")
	}
	// keep=1 → 2 victims; first fails, second succeeds → 1 reported deleted.
	if len(deleted) != 1 {
		t.Errorf("deleted = %v, want exactly the one that succeeded", deleted)
	}
}

// countingDeleteStorage is a List-backed Storage whose Delete fails for a
// chosen victim index so the partial-success path in PruneOldest is exercised.
type countingDeleteStorage struct {
	names     []string
	failOnIdx int
	delCount  int
}

func (s *countingDeleteStorage) Put(context.Context, string, []byte) error { return nil }
func (s *countingDeleteStorage) Get(context.Context, string) ([]byte, error) {
	return nil, snapshot.ErrSnapshotNotFound
}
func (s *countingDeleteStorage) List(context.Context) ([]string, error) {
	out := make([]string, len(s.names))
	copy(out, s.names)
	return out, nil
}
func (s *countingDeleteStorage) Delete(_ context.Context, name string) error {
	idx := s.delCount
	s.delCount++
	if idx == s.failOnIdx {
		return errBoom
	}
	// remove from names so List reflects the deletion
	for i, n := range s.names {
		if n == name {
			s.names = append(s.names[:i], s.names[i+1:]...)
			break
		}
	}
	return nil
}

// errTracker is a boundary error-fake for bootstrap.Tracker — there is no
// failing in-memory Tracker, so this exercises the read/write fault branches
// in advanceBootstrap.
type errTracker struct {
	appliedErr error
	markErr    error
	version    int
}

func (t *errTracker) AppliedVersion(context.Context, string) (int, error) {
	return t.version, t.appliedErr
}
func (t *errTracker) MarkApplied(context.Context, string, int, string) error { return t.markErr }
func (t *errTracker) Close() error                                           { return nil }

// TestAdvanceBootstrap_ReadError surfaces an AppliedVersion fault.
func TestAdvanceBootstrap_ReadError(t *testing.T) {
	ctx := context.Background()
	snap := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap_read-err",
		SourceNamespace: "ns",
		BootstrapState:  snapshot.BootstrapState{Namespace: "sso-server", AppliedVersion: 3},
	}
	r := &snapshot.Restorer{
		Clients: defaultimpl.NewMemoryClientStore(),
		Tracker: &errTracker{appliedErr: errBoom},
	}
	_, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err == nil {
		t.Error("advanceBootstrap must propagate AppliedVersion error")
	}
}

// TestAdvanceBootstrap_MarkError surfaces a MarkApplied fault (snapshot is
// newer so the mark is actually attempted).
func TestAdvanceBootstrap_MarkError(t *testing.T) {
	ctx := context.Background()
	snap := &snapshot.Snapshot{
		SchemaVersion:   snapshot.SchemaVersion,
		SnapshotID:      "snap_mark-err",
		SourceNamespace: "ns",
		BootstrapState:  snapshot.BootstrapState{Namespace: "sso-server", AppliedVersion: 7},
	}
	r := &snapshot.Restorer{
		Clients: defaultimpl.NewMemoryClientStore(),
		Tracker: &errTracker{version: 1, markErr: errBoom}, // 1 < 7 → mark attempted
	}
	_, err := r.Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err == nil {
		t.Error("advanceBootstrap must propagate MarkApplied error")
	}
}
