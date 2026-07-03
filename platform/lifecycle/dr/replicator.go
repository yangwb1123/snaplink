package dr

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/shared/spi"
)

// Defaults applied by NewSnapshotReplicator for zero/absent config values.
const (
	DefaultReplicationInterval = 15 * time.Minute
	DefaultReplicationKeep     = 7
)

// replicaPrefix / replicaExt name the files the replicator writes AND the
// only files its retention pruner will ever delete — foreign files sharing
// the DR mount are never touched. The prefix mirrors the snapshot ID
// convention (snap_<utc-stamp>_<rand>), whose fixed-width timestamp makes
// lexicographic order equal chronological order — retention relies on it.
const (
	replicaPrefix = "snap_"
	replicaExt    = ".snap"
)

// ErrReplicaChecksumMismatch means the bytes read back from the DR target
// after the copy did not hash to the exported bytes' SHA-256 — the replica
// was discarded (a corrupted DR copy is worse than a missing one: it fails
// exactly when it is needed).
var ErrReplicaChecksumMismatch = errors.New("dr: replica checksum mismatch after copy")

// ExportFunc produces one sealed snapshot artifact: its storage name (the
// snapshot ID, snap_-prefixed) and the envelope bytes. cmd adapts the
// snapshot subsystem's Snapshotter+Pipeline behind this seam so this
// package never imports the interfaces layer.
type ExportFunc func(ctx context.Context) (name string, data []byte, err error)

// SnapshotReplicator periodically exports a sealed snapshot and copies it
// to the DR replica mount, verifying the copy by checksum and keeping only
// the newest Keep replicas. Export/copy failures are fail-open: logged,
// surfaced via LastError + readiness, retried next tick — never fatal.
type SnapshotReplicator struct {
	Export    ExportFunc
	TargetDir string
	Interval  time.Duration
	Keep      int
	Logger    spi.Logger

	now func() time.Time

	mu          sync.Mutex
	lastSuccess time.Time
	lastName    string
	lastError   string
}

// NewSnapshotReplicator validates the wiring and applies defaults.
func NewSnapshotReplicator(export ExportFunc, targetDir string, interval time.Duration, keep int, logger spi.Logger) (*SnapshotReplicator, error) {
	if export == nil {
		return nil, errors.New("dr: replicator export func required")
	}
	abs, err := filepath.Abs(strings.TrimSpace(targetDir))
	if err != nil || strings.TrimSpace(targetDir) == "" {
		return nil, fmt.Errorf("dr: replicator target dir %q invalid: %v", targetDir, err)
	}
	if interval <= 0 {
		interval = DefaultReplicationInterval
	}
	if keep <= 0 {
		keep = DefaultReplicationKeep
	}
	if logger == nil {
		logger = spi.NopLogger{}
	}
	return &SnapshotReplicator{
		Export: export, TargetDir: abs, Interval: interval, Keep: keep,
		Logger: logger, now: time.Now,
	}, nil
}

// Run starts the background replication loop and returns a channel closed
// when the loop exits (after ctx cancellation). The first cycle fires
// immediately: readiness compares the newest replica's age against the RPO
// target, so waiting a full interval would leave a fresh boot "not ready"
// for no operational reason.
func (r *SnapshotReplicator) Run(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.replicateLogged(ctx)
		ticker := time.NewTicker(r.Interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.replicateLogged(ctx)
			}
		}
	}()
	return done
}

func (r *SnapshotReplicator) replicateLogged(ctx context.Context) {
	if err := r.ReplicateOnce(ctx); err != nil && ctx.Err() == nil {
		r.Logger.Error("dr: snapshot replication failed", "error", err, "target_dir", r.TargetDir)
	}
}

// ReplicateOnce runs one export -> copy -> verify -> prune cycle. Exported
// for tests and for operator-triggered "replicate now" tooling.
func (r *SnapshotReplicator) ReplicateOnce(ctx context.Context) error {
	name, data, err := r.Export(ctx)
	if err != nil {
		return r.fail(fmt.Errorf("dr: export: %w", err))
	}
	fileName, err := replicaFileName(name)
	if err != nil {
		return r.fail(err)
	}
	if err := r.copyVerified(fileName, data); err != nil {
		return r.fail(err)
	}
	if pruned, perr := pruneReplicas(r.TargetDir, r.Keep); perr != nil {
		// A prune failure does not invalidate the fresh, verified replica —
		// report success but keep the error visible to operators.
		r.Logger.Error("dr: replica retention prune failed", "error", perr, "pruned", pruned)
	}
	r.mu.Lock()
	r.lastSuccess, r.lastName, r.lastError = r.now(), fileName, ""
	r.mu.Unlock()
	return nil
}

func (r *SnapshotReplicator) fail(err error) error {
	r.mu.Lock()
	r.lastError = err.Error()
	r.mu.Unlock()
	return err
}

// copyVerified writes data to a temp file in the target dir, reads it back,
// compares SHA-256 digests, and only then renames it into place — a replica
// file is either complete and verified or absent.
func (r *SnapshotReplicator) copyVerified(fileName string, data []byte) error {
	if err := os.MkdirAll(r.TargetDir, 0o700); err != nil {
		return fmt.Errorf("dr: mkdir %q: %w", r.TargetDir, err)
	}
	tmp, err := os.CreateTemp(r.TargetDir, ".tmp-"+fileName+"-*")
	if err != nil {
		return fmt.Errorf("dr: tempfile: %w", err)
	}
	tmpName := tmp.Name()
	_, werr := tmp.Write(data)
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = verifyChecksum(tmpName, sha256.Sum256(data))
	}
	if werr != nil {
		_ = os.Remove(tmpName)
		return werr
	}
	if err := os.Rename(tmpName, filepath.Join(r.TargetDir, fileName)); err != nil {
		_ = os.Remove(tmpName)
		return fmt.Errorf("dr: rename: %w", err)
	}
	return nil
}

func verifyChecksum(path string, want [sha256.Size]byte) error {
	got, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("dr: read-back: %w", err)
	}
	sum := sha256.Sum256(got)
	if !bytes.Equal(sum[:], want[:]) {
		return ErrReplicaChecksumMismatch
	}
	return nil
}

// replicaFileName validates the export name (defense against a path-shaped
// snapshot ID escaping the target dir) and appends the replica extension.
func replicaFileName(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || strings.Contains(name, "..") {
		return "", fmt.Errorf("dr: unsafe replica name %q", name)
	}
	if !strings.HasPrefix(name, replicaPrefix) {
		// Retention ordering depends on the snap_<stamp> convention; a
		// custom name generator without it would make pruning arbitrary.
		return "", fmt.Errorf("dr: replica name %q lacks the %q prefix", name, replicaPrefix)
	}
	if !strings.HasSuffix(name, replicaExt) {
		name += replicaExt
	}
	return name, nil
}

// pruneReplicas deletes all but the newest keep replica files. Only files
// matching the replica naming convention are candidates.
func pruneReplicas(dir string, keep int) (int, error) {
	names, err := listReplicaNames(dir)
	if err != nil || len(names) <= keep {
		return 0, err
	}
	sort.Strings(names)
	var pruned int
	var firstErr error
	for _, n := range names[:len(names)-keep] {
		if rerr := os.Remove(filepath.Join(dir, n)); rerr != nil {
			if firstErr == nil {
				firstErr = rerr
			}
			continue
		}
		pruned++
	}
	return pruned, firstErr
}

func listReplicaNames(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("dr: list %q: %w", dir, err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), replicaPrefix) && strings.HasSuffix(e.Name(), replicaExt) {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// LatestReplica returns the newest retained replica's file name and bytes —
// the freshest verified copy the RecoveryOrchestrator's integrity + restore
// steps recover from. Returns ErrNoReplica when the target dir holds none.
// The snap_<utc-stamp>_ naming convention makes lexicographic order equal
// chronological order, so the last name after sorting is the newest.
func (r *SnapshotReplicator) LatestReplica() (string, []byte, error) {
	names, err := listReplicaNames(r.TargetDir)
	if err != nil {
		return "", nil, err
	}
	if len(names) == 0 {
		return "", nil, ErrNoReplica
	}
	sort.Strings(names)
	name := names[len(names)-1]
	data, err := os.ReadFile(filepath.Join(r.TargetDir, name))
	if err != nil {
		return "", nil, fmt.Errorf("dr: read replica %q: %w", name, err)
	}
	return name, data, nil
}

// LastSuccess returns the wall-clock time of the last verified replication;
// ok is false when none has succeeded yet.
func (r *SnapshotReplicator) LastSuccess() (time.Time, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastSuccess, !r.lastSuccess.IsZero()
}

// LastError returns the most recent cycle failure, or "" when the last
// cycle succeeded (or none ran yet).
func (r *SnapshotReplicator) LastError() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastError
}

// ReplicaFile is one retained replica in the DR target dir.
type ReplicaFile struct {
	Name       string    `json:"name"`
	SizeBytes  int64     `json:"size_bytes"`
	ModifiedAt time.Time `json:"modified_at"`
}

// Inventory lists the retained replicas, oldest first.
func (r *SnapshotReplicator) Inventory() ([]ReplicaFile, error) {
	names, err := listReplicaNames(r.TargetDir)
	if err != nil {
		if os.IsNotExist(err) || errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	sort.Strings(names)
	out := make([]ReplicaFile, 0, len(names))
	for _, n := range names {
		fi, serr := os.Stat(filepath.Join(r.TargetDir, n))
		if serr != nil {
			continue
		}
		out = append(out, ReplicaFile{Name: n, SizeBytes: fi.Size(), ModifiedAt: fi.ModTime().UTC()})
	}
	return out, nil
}
