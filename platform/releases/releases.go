// Package releases is the admin app version pin / rollback layer
// (Phase D-3). A Release is the pairing of a Frontend bundle and a
// Backend artifact released together by CI/CD; operators Pin one as
// "current" and Rollback to a previous one when needed.
//
// The split is intentional: ReleaseStore handles persistence (Register
// / Get / List / Delete + a separate "current" pointer), and a
// Registry layered on top owns the operational lifecycle (Pin /
// Rollback with a Pinner SPI for site-specific deploy mechanics).
//
// Releases reference an optional ConfigSnapshot (the Phase D-2
// snapshot id) so a rollback can restore the matching admin-managed
// state — clients, users, roles — alongside flipping the artifacts.
package releases

import (
	"context"
	"errors"
	"time"
)

// Release is one paired Frontend+Backend deployment artifact set,
// stamped with the schema version and an optional snapshot pointer.
type Release struct {
	ID             string    `json:"id"`
	Channel        string    `json:"channel,omitempty"`
	Frontend       Artifact  `json:"frontend"`
	Backend        Artifact  `json:"backend"`
	SchemaVersion  int       `json:"schema_version"`
	ConfigSnapshot string    `json:"config_snapshot,omitempty"`
	ReleasedAt     time.Time `json:"released_at"`
	ReleasedBy     string    `json:"released_by,omitempty"`
	Notes          string    `json:"notes,omitempty"`
}

// Artifact identifies one half (frontend or backend) of a Release.
// At least one of GitRef / URI must be set; SHA256 / Digest are the
// integrity hooks the Pinner verifies before flipping.
type Artifact struct {
	GitRef string `json:"git_ref,omitempty"`
	URI    string `json:"uri,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Digest string `json:"digest,omitempty"`
}

// Channel constants. ReleaseStore implementations don't enforce these
// — they're conventions for filtering in admin UIs.
const (
	ChannelStable   = "stable"
	ChannelCanary   = "canary"
	ChannelRollback = "rollback"
)

// ReleaseStore persists Releases. Implementations live in store/*.
// Current is tracked separately from the Release set so that pinning
// a different release is one mutation, not a re-register.
type ReleaseStore interface {
	// Register stores r. ErrReleaseExists when r.ID is already in use —
	// callers must Delete first or pick a fresh id.
	Register(ctx context.Context, r *Release) error
	// Get returns the Release with the given id. ErrReleaseNotFound when
	// missing.
	Get(ctx context.Context, id string) (*Release, error)
	// List enumerates known releases in arbitrary order. Implementations
	// SHOULD return a stable ordering when feasible (file backend sorts
	// by ID; memory does the same on List).
	List(ctx context.Context) ([]*Release, error)
	// Delete removes id. Idempotent — missing returns nil. If id is the
	// current release, Current() is also cleared.
	Delete(ctx context.Context, id string) error
	// SetCurrent atomically marks id as the current release. ErrReleaseNotFound
	// when id is unknown.
	SetCurrent(ctx context.Context, id string) error
	// Current returns the currently-pinned release. ErrNoCurrent when
	// nothing is pinned yet (fresh deployments).
	Current(ctx context.Context) (*Release, error)
	// ClearCurrent removes the "current" pointer without touching the
	// release records. Useful for tests and for "stop serving" workflows.
	ClearCurrent(ctx context.Context) error
}

// Sentinel errors. Admin RPCs map these to gRPC codes; Registry
// callers branch on them via errors.Is.
var (
	ErrReleaseNotFound = errors.New("releases: not found")
	ErrReleaseExists   = errors.New("releases: already exists")
	ErrInvalidPair     = errors.New("releases: frontend and backend artifacts both required")
	ErrNoCurrent       = errors.New("releases: no current release")
	ErrSchemaRegress   = errors.New("releases: target schema version is older than current; use Rollback")
)

// Validate sanity-checks a Release before persistence. Both halves of
// the pair must carry at least one identifying field — the design
// goal is to keep operators from registering one-sided releases that
// can't actually be deployed.
func (r *Release) Validate() error {
	if r.ID == "" {
		return errors.New("releases: id required")
	}
	if r.Frontend.GitRef == "" && r.Frontend.URI == "" {
		return ErrInvalidPair
	}
	if r.Backend.GitRef == "" && r.Backend.URI == "" {
		return ErrInvalidPair
	}
	return nil
}
