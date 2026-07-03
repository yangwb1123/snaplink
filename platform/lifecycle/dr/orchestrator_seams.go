package dr

import (
	"context"
	"crypto/sha256"
	"errors"
	"sync"
)

// ErrNoReplica means the DR target dir holds no replica to recover from: the
// orchestrator cannot verify or restore what does not exist, so a recovery
// run aborts at the integrity step rather than promoting onto an empty
// target.
var ErrNoReplica = errors.New("dr: no replica available to recover from")

// ErrReplicaIntegrity means a replica's bytes did not match the integrity
// expectation (a recomputed digest differs, or the snapshot envelope failed
// its own checksum). "A corrupted DR is worse than a missing one" — the
// orchestrator refuses to fail over onto it.
var ErrReplicaIntegrity = errors.New("dr: replica failed integrity verification")

// ReplicaIntegrityVerifier validates that a replicated snapshot artifact is
// internally consistent BEFORE the orchestrator restores from it. This
// package cannot parse the snapshot envelope (interfaces/snapshot lives an
// upward layer platform must not import), so integrity checking is a seam:
// cmd and the drill harness wire a closure over the snapshot Pipeline (whose
// Load recomputes + compares the embedded plaintext SHA-256), catching a
// bit-rotted or tampered DR replica. This is the step that refuses to fail
// over onto bad data.
type ReplicaIntegrityVerifier interface {
	VerifyReplica(ctx context.Context, name string, data []byte) error
}

// VerifyReplicaFunc adapts a bare func to ReplicaIntegrityVerifier so callers
// can wire a Pipeline-backed closure without a named type.
type VerifyReplicaFunc func(ctx context.Context, name string, data []byte) error

// VerifyReplica implements ReplicaIntegrityVerifier.
func (f VerifyReplicaFunc) VerifyReplica(ctx context.Context, name string, data []byte) error {
	return f(ctx, name, data)
}

// MemoryReplicaVerifier is a self-contained ReplicaIntegrityVerifier that
// checks a replica's bytes against a SHA-256 digest registered under its
// name. Real, not a mock: the orchestrator's own unit tests register the
// digest at replication time and re-verify at recovery time, exercising both
// the clean-verify and corruption-detected-abort paths without the full
// snapshot envelope machinery (the drill harness wires the real Pipeline-
// backed verifier instead). Safe for concurrent use.
type MemoryReplicaVerifier struct {
	mu      sync.Mutex
	digests map[string][sha256.Size]byte
}

// NewMemoryReplicaVerifier returns an empty verifier.
func NewMemoryReplicaVerifier() *MemoryReplicaVerifier {
	return &MemoryReplicaVerifier{digests: make(map[string][sha256.Size]byte)}
}

// Register records the expected digest of name's bytes (called at
// replication time). A later VerifyReplica of the same name with different
// bytes fails ErrReplicaIntegrity.
func (m *MemoryReplicaVerifier) Register(name string, data []byte) {
	sum := sha256.Sum256(data)
	m.mu.Lock()
	m.digests[name] = sum
	m.mu.Unlock()
}

// VerifyReplica implements ReplicaIntegrityVerifier. An unregistered name is
// treated as unverifiable and fails closed — the whole point of the step is
// to refuse unknown or altered data.
func (m *MemoryReplicaVerifier) VerifyReplica(_ context.Context, name string, data []byte) error {
	m.mu.Lock()
	want, ok := m.digests[name]
	m.mu.Unlock()
	if !ok || sha256.Sum256(data) != want {
		return ErrReplicaIntegrity
	}
	return nil
}

// ReplicaPromoter performs the deployment-specific act of promoting a DR
// replica to primary (repoint DNS/LB, flip a hot-standby to read-write, ...).
// The actual promotion lives OUTSIDE this process, so it is a seam: the
// default MemoryReplicaPromoter is a no-op recorder used in drills (which
// must NOT actually cut traffic over) and in tests.
type ReplicaPromoter interface {
	Promote(ctx context.Context) error
}

// PromoteFunc adapts a bare func to ReplicaPromoter.
type PromoteFunc func(ctx context.Context) error

// Promote implements ReplicaPromoter.
func (f PromoteFunc) Promote(ctx context.Context) error { return f(ctx) }

// MemoryReplicaPromoter is the no-op ReplicaPromoter: it records how many
// times Promote was called (so a drill can assert the step actually ran) and,
// when FailWith is set, returns that error to exercise the orchestrator's
// abort-on-promote-failure path. Safe for concurrent use.
type MemoryReplicaPromoter struct {
	// FailWith, when non-nil, is returned by every Promote call.
	FailWith error

	mu    sync.Mutex
	calls int
}

// Promote implements ReplicaPromoter.
func (m *MemoryReplicaPromoter) Promote(_ context.Context) error {
	m.mu.Lock()
	m.calls++
	m.mu.Unlock()
	return m.FailWith
}

// Calls returns how many times Promote has been invoked.
func (m *MemoryReplicaPromoter) Calls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.calls
}

// StateRestorer applies a verified replica's control-plane state into the
// (DR-target) stores, reusing the existing snapshot restore path. Like the
// verifier it is a seam because Restore lives in interfaces/snapshot (an
// upward layer platform must not import): cmd and the drill harness wire a
// closure over Pipeline.Load + snapshot.Restorer. The returned string is a
// short human summary for the recovery report.
type StateRestorer interface {
	RestoreReplica(ctx context.Context, name string, data []byte) (string, error)
}

// RestoreReplicaFunc adapts a bare func to StateRestorer.
type RestoreReplicaFunc func(ctx context.Context, name string, data []byte) (string, error)

// RestoreReplica implements StateRestorer.
func (f RestoreReplicaFunc) RestoreReplica(ctx context.Context, name string, data []byte) (string, error) {
	return f(ctx, name, data)
}

// MemoryStateRestorer is a self-contained StateRestorer that records the last
// replica handed to it (name + byte length) and returns a canned summary.
// Real, not a mock: orchestrator unit tests assert the restore step received
// the SAME bytes the integrity step verified. FailWith exercises the
// abort-on-restore-failure path. Safe for concurrent use.
type MemoryStateRestorer struct {
	// FailWith, when non-nil, is returned by every RestoreReplica call.
	FailWith error

	mu       sync.Mutex
	lastName string
	lastLen  int
	calls    int
}

// RestoreReplica implements StateRestorer.
func (m *MemoryStateRestorer) RestoreReplica(_ context.Context, name string, data []byte) (string, error) {
	m.mu.Lock()
	m.lastName, m.lastLen, m.calls = name, len(data), m.calls+1
	m.mu.Unlock()
	if m.FailWith != nil {
		return "", m.FailWith
	}
	return "restored " + name, nil
}

// Last returns the name + byte length of the most recently restored replica
// and the total restore-call count.
func (m *MemoryStateRestorer) Last() (name string, size, calls int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastName, m.lastLen, m.calls
}

// Interface guards. Live in this implementation package (never the interface
// site) to avoid an import cycle, per the repo convention.
var (
	_ ReplicaIntegrityVerifier = (*MemoryReplicaVerifier)(nil)
	_ ReplicaIntegrityVerifier = VerifyReplicaFunc(nil)
	_ ReplicaPromoter          = (*MemoryReplicaPromoter)(nil)
	_ ReplicaPromoter          = PromoteFunc(nil)
	_ StateRestorer            = (*MemoryStateRestorer)(nil)
	_ StateRestorer            = RestoreReplicaFunc(nil)
)
