package configaudit

import (
	"context"
	"errors"
	"time"
)

// ErrSnapshotUnavailable is returned by a HandlerDeps snapshot accessor
// (AppliedConfigSnapshot / RunningConfigSnapshot) when no config-snapshot
// source was wired (the server never received WithConfigSnapshots). The
// HTTP handlers use errors.Is against this to distinguish "feature not
// configured" (501) from a genuine read failure (500).
var ErrSnapshotUnavailable = errors.New("configaudit: no config snapshot wired")

// ErrNoAppliedVersion is returned by Store.Applied / Store.Rollback before
// the first successful Apply: there is no declared applied-config baseline
// yet (or, for Rollback, the latest baseline has no predecessor to restore).
// The HTTP handlers use errors.Is against this to distinguish "nothing to
// roll back" (409 config_apply_no_previous) from a genuine store failure
// (500).
var ErrNoAppliedVersion = errors.New("configaudit: no applied config version")

// Canary lifecycle errors are intentionally separate from the baseline
// errors: the HTTP layer maps the bounded, operator-actionable cases to
// stable wire codes while the store keeps the atomic state-machine boundary.
var (
	ErrNoCanary            = errors.New("configaudit: no canary state")
	ErrCanaryInProgress    = errors.New("configaudit: canary already observing")
	ErrCanaryNoBaseline    = errors.New("configaudit: canary needs an applied baseline")
	ErrCanaryConflict      = errors.New("configaudit: canary version is no longer current")
	ErrCanaryUnavailable   = errors.New("configaudit: canary store is unavailable")
	ErrRollbackConflict    = errors.New("configaudit: rollback version is no longer current")
	ErrRollbackUnavailable = errors.New("configaudit: conditional rollback is unavailable")
)

// Op is one RFC 6902 JSON Patch operation. Only add/replace/remove are
// produced by Diff (see its doc for why move/copy/test are out of scope).
type Op struct {
	Op    string `json:"op"`
	Path  string `json:"path"`
	Value any    `json:"value,omitempty"`
}

// Entry is one recorded runtime-configuration change: what changed
// (Resource + ResourceID), who changed it (Actor, sourced from the admin
// auth context), and the redacted RFC 6902 JSON Patch describing the
// change. Mirrors the config_history table shape from
// docs/expansion-volume2-2026-07-01.md §3.
type Entry struct {
	ID         string    `json:"id"`
	RecordedAt time.Time `json:"recorded_at"`
	Actor      string    `json:"actor"`
	TenantID   string    `json:"tenant_id,omitempty"`
	Resource   string    `json:"resource"` // "client" | "tenant" | "policy" | ...
	ResourceID string    `json:"resource_id"`
	Patch      []Op      `json:"patch"`
	// PrevHash optionally chains entries for tamper-evidence, mirroring
	// platform/audit's hash chain. Neither MemoryStore nor the change-
	// capture hook in this SDK populate it today — the column exists so a
	// Store implementation (or a future WithHashChain-style option) can add
	// chaining without a schema change.
	PrevHash string `json:"prev_hash,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// Filter narrows Store.List. A zero Filter lists everything the store
// retains, newest first.
type Filter struct {
	Resource string    // exact match; empty = any resource
	Since    time.Time // zero = no lower bound
	Limit    int       // <= 0 = the store's default page size
}

// resourceConfigApply is the config_history "resource" column value every
// apply/rollback entry carries — the peer-config baseline is a whole-config
// resource, distinct from the client/tenant/policy change-capture rows.
const resourceConfigApply = "config"

// AppliedVersion is one recorded "applied peer configuration" baseline: a
// declared target state for this cluster's config-audit views, captured
// from a peer snapshot by POST /api/v1/admin/config/apply (and restored by
// .../rollback). Snapshot is ALWAYS the REDACTED peer snapshot — the raw
// request snapshot is used only for the digest check and the on-the-wire
// diff, never persisted (see Redact). PrevID chains versions append-only so
// rollback can restore the immediately-previous baseline.
type AppliedVersion struct {
	ID        string         `json:"id"`
	AppliedAt time.Time      `json:"applied_at"`
	Actor     string         `json:"actor"`
	Digest    string         `json:"digest"` // peer config digest (split-brain fingerprint)
	Reason    string         `json:"reason"`
	PrevID    string         `json:"prev_id,omitempty"`
	Snapshot  map[string]any `json:"snapshot"` // redacted
}

// CanaryStatus is the persisted lifecycle state for one configuration
// canary. Only Observing is active; terminal states are retained until the
// next canary replaces the single current record.
type CanaryStatus string

const (
	CanaryObserving  CanaryStatus = "observing"
	CanaryConfirmed  CanaryStatus = "confirmed"
	CanaryRolledBack CanaryStatus = "rolled_back"
)

// CanaryState is the redacted, durable evidence for a canary observation. It
// intentionally stores identifiers and timing only; the candidate snapshot
// remains in the append-only AppliedVersion chain.
type CanaryState struct {
	ID                string       `json:"id"`
	VersionID         string       `json:"version_id"`
	PreviousVersionID string       `json:"previous_version_id"`
	Actor             string       `json:"actor"`
	Digest            string       `json:"digest"`
	Reason            string       `json:"reason"`
	StartedAt         time.Time    `json:"started_at"`
	Deadline          time.Time    `json:"deadline"`
	Status            CanaryStatus `json:"status"`
	Detail            string       `json:"detail,omitempty"`
}

// Store persists config_history entries. Every SDK concern is an interface
// plus a real memory implementation (AGENTS.md §0.6, "no mocks") —
// MemoryStore is this package's; configaudit/sqlite is the durable backend.
type Store interface {
	// Record appends e. Implementations assign e.ID / e.RecordedAt when the
	// caller left them zero.
	Record(ctx context.Context, e Entry) error
	// List returns entries matching f, newest first.
	List(ctx context.Context, f Filter) ([]Entry, error)
	// Apply atomically records v as the new applied-config baseline (linking
	// v.PrevID to the current latest), appending a config_history entry
	// (resource "config", redacted patch Diff(current, v)) in the SAME
	// write, and returns the stored version with ID / AppliedAt assigned.
	// A failure must leave the previous baseline and history untouched
	// (transactional — no half-state).
	Apply(ctx context.Context, v AppliedVersion) (AppliedVersion, error)
	// Applied returns the latest applied-config baseline, or ErrNoAppliedVersion
	// before the first Apply.
	Applied(ctx context.Context) (AppliedVersion, error)
	// Rollback atomically re-declares the previous baseline as the new latest
	// (a NEW version whose Snapshot is the previous version's — the chain stays
	// append-only), appending a config_history entry in the same write. Returns
	// the restored version. ErrNoAppliedVersion when there is no baseline at
	// all or the latest baseline has no predecessor.
	Rollback(ctx context.Context, actor, reason string) (AppliedVersion, error)
}

// CanaryStore is the optional atomic extension used by the canary apply
// path. Keeping it separate from Store preserves compatibility for custom
// config-history backends: deployments without this extension retain the
// existing non-canary API and receive a deterministic 501 for canary mode.
// The built-in Memory and SQLite stores implement this interface.
type CanaryStore interface {
	Store
	// BeginCanary records the candidate baseline and its observing state in
	// one atomic operation. An existing applied baseline is mandatory so the
	// candidate always has a rollback target.
	BeginCanary(ctx context.Context, v AppliedVersion, state CanaryState) (AppliedVersion, CanaryState, error)
	// Canary returns the current lifecycle record, or ErrNoCanary when none
	// has been recorded.
	Canary(ctx context.Context) (CanaryState, error)
	// ConfirmCanary transitions an observing record to confirmed.
	ConfirmCanary(ctx context.Context, id string) error
	// RollbackCanary atomically restores the recorded predecessor and marks
	// the observing record rolled_back. It refuses to touch a newer baseline.
	RollbackCanary(ctx context.Context, id, actor, reason string) (AppliedVersion, CanaryState, error)
}

// ConditionalRollbackStore is the optional compare-and-swap extension used
// by explicit operator rollback. Keeping it separate from Store preserves
// compatibility for custom backends and makes an unguarded manual rollback
// remain byte-compatible. Built-in Memory and SQLite stores implement the
// atomic expected-version check.
type ConditionalRollbackStore interface {
	Store
	// RollbackIfCurrent restores the previous baseline only when the latest
	// applied version still has expectedID. A mismatch changes nothing and
	// returns ErrRollbackConflict.
	RollbackIfCurrent(ctx context.Context, expectedID, actor, reason string) (AppliedVersion, error)
}
