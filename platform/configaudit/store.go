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

// Store persists config_history entries. Every SDK concern is an interface
// plus a real memory implementation (AGENTS.md §0.6, "no mocks") —
// MemoryStore is this package's; configaudit/sqlite is the durable backend.
type Store interface {
	// Record appends e. Implementations assign e.ID / e.RecordedAt when the
	// caller left them zero.
	Record(ctx context.Context, e Entry) error
	// List returns entries matching f, newest first.
	List(ctx context.Context, f Filter) ([]Entry, error)
}
