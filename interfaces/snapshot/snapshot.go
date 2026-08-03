// Package snapshot is the export / restore layer for the SSO admin
// state. A Snapshot bundles every operator-managed resource — clients,
// users, role definitions, role assignments, menus, and network
// policies — alongside the bootstrap Tracker's namespace state, into a
// single self-describing artifact.
//
// Use cases:
//
//   - Stand up a new node from a known-good baseline.
//   - Migrate config across air-gapped networks.
//   - Disaster-recovery drills (export from prod, restore into staging).
//   - Time-travel debugging (snapshot before a risky change).
//
// The Snapshot type is the in-memory representation. The wire format is
// produced by codec.Codec (JSON by default), optionally encrypted by an
// encryption.Sealer, and persisted by storage.Storage. See pipeline.go
// for the Save / Load helpers that compose the three.
//
// Active sessions and live tokens are intentionally excluded from
// snapshots: their identity-bearing nature makes them dangerous to
// move across nodes.
package snapshot

import (
	"errors"
	"slices"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// SchemaVersion is the version of the Snapshot envelope. Bump when a
// breaking field change happens; readers refuse unknown versions.
const SchemaVersion = "2"

// KindSafetySnapshot marks an artifact produced as the pre-restore safety
// net (the undo artifact for rollback / manual operator recovery). Ordinary
// exports carry an empty kind.
const KindSafetySnapshot = "safety"

// Snapshot is the in-memory representation of an exported state.
type Snapshot struct {
	SchemaVersion   string             `json:"schema_version"`
	SnapshotID      string             `json:"snapshot_id"`
	TakenAtUnix     int64              `json:"taken_at_unix"`
	SourceNamespace string             `json:"source_namespace"`
	SourceNodeID    string             `json:"source_node_id,omitempty"`
	BootstrapState  BootstrapState     `json:"bootstrap_state"`
	Categories      []ResourceCategory `json:"categories"`
	Resources       Resources          `json:"resources"`

	// Kind classifies the artifact: empty = ordinary export,
	// KindSafetySnapshot = pre-restore safety net. Deliberately NOT
	// serialized into the body (json:"-"): the JSON codec decodes with
	// DisallowUnknownFields, so a body-level key would make safety
	// artifacts undecodable by pre-change binaries (a wire-compat
	// regression). The kind travels in the SealedEnvelope HEADER instead
	// (Pipeline.Save mirrors it), which both old and new readers tolerate
	// as an additive JSON field and which retention/List can read without
	// decryption.
	Kind string `json:"-"`
}

// BootstrapState captures the highest applied step version for the
// snapshot's namespace at the moment of export. Restorers may opt to
// advance the local tracker to this version so seed steps don't re-run.
type BootstrapState struct {
	Namespace      string `json:"namespace"`
	AppliedVersion int    `json:"applied_version"`
}

// Resources groups every operator-managed resource into a single
// container. Each field corresponds to one ResourceCategory; a nil
// slice / empty map means "nothing of this kind in the snapshot" and
// is treated as a no-op on restore (NOT as "delete everything").
type Resources struct {
	Tenants       []*tenant.Tenant                  `json:"tenants,omitempty"`
	TenantDomains []*tenant.Domain                  `json:"tenant_domains,omitempty"`
	Connections   []*connections.Connection         `json:"connections,omitempty"`
	Clients       []*sso.Client                     `json:"clients,omitempty"`
	Users         []*sso.User                       `json:"users,omitempty"`
	Pairwise      []security.PairwiseSubjectMapping `json:"pairwise_subjects,omitempty"`
	Roles         []ClientRoles                     `json:"roles,omitempty"`
	Assignments   []ClientAssignments               `json:"assignments,omitempty"`
	Menus         []ClientMenus                     `json:"menus,omitempty"`
	NetPolicy     []*netpolicy.Policy               `json:"netpolicy,omitempty"`
}

// ClientRoles is one (clientID, []Role) tuple for the per-client
// permissions data model.
type ClientRoles struct {
	ClientID string             `json:"client_id"`
	Roles    []permissions.Role `json:"roles"`
}

// ClientAssignments is one (clientID, []Assignment) tuple.
type ClientAssignments struct {
	ClientID    string                   `json:"client_id"`
	Assignments []permissions.Assignment `json:"assignments"`
}

// ClientMenus is one (clientID, MenuTree) tuple.
type ClientMenus struct {
	ClientID string               `json:"client_id"`
	Menus    permissions.MenuTree `json:"menus"`
}

// ResourceCategory enumerates the categories an operator may include /
// exclude when exporting or restoring. Used as keys in ExportOptions.Exclude
// and RestoreOptions.Exclude.
type ResourceCategory string

const (
	CategoryTenants       ResourceCategory = "tenants"
	CategoryTenantDomains ResourceCategory = "tenant_domains"
	CategoryConnections   ResourceCategory = "connections"
	CategoryClients       ResourceCategory = "clients"
	CategoryUsers         ResourceCategory = "users"
	CategoryPairwise      ResourceCategory = "pairwise_subjects"
	CategoryRoles         ResourceCategory = "roles"
	CategoryAssignments   ResourceCategory = "assignments"
	CategoryMenus         ResourceCategory = "menus"
	CategoryNetPolicy     ResourceCategory = "netpolicy"
)

// AllCategories is the canonical category list, used for "include all"
// defaulting. Do not mutate the returned slice.
func AllCategories() []ResourceCategory {
	return []ResourceCategory{
		CategoryTenants, CategoryTenantDomains, CategoryConnections,
		CategoryClients, CategoryUsers, CategoryPairwise, CategoryRoles,
		CategoryAssignments, CategoryMenus, CategoryNetPolicy,
	}
}

// excluded reports whether c appears in the slice.
func excluded(c ResourceCategory, excludes []ResourceCategory) bool {
	return slices.Contains(excludes, c)
}

// ExcludedListed reports whether c appears in excludes. Exported for the
// rollback-scope computation's callers (the admin orchestrator pins the
// rollback exclusion set with it); excluded is the internal shorthand used
// by the restore plan.
func ExcludedListed(excludes []ResourceCategory, c ResourceCategory) bool {
	return excluded(c, excludes)
}

// IsValidSchemaVersion reports whether v is one this build can handle.
// Centralized so the codec, restorer, and admin RPC all agree.
func IsValidSchemaVersion(v string) bool { return v == "1" || v == SchemaVersion }

// IncludesCategory reports whether restore may reconcile c. Version 1 can only
// describe its legacy categories. A nil v2 manifest preserves compatibility
// for in-process callers; exported v2 snapshots always use an explicit list.
func (s *Snapshot) IncludesCategory(c ResourceCategory) bool {
	if s.SchemaVersion == "1" {
		return slices.Contains(legacyCategories(), c)
	}
	if s.Categories == nil {
		return true
	}
	return slices.Contains(s.Categories, c)
}

func legacyCategories() []ResourceCategory {
	return []ResourceCategory{
		CategoryClients, CategoryUsers, CategoryRoles,
		CategoryAssignments, CategoryMenus, CategoryNetPolicy,
	}
}

// Sentinel errors. Admin RPCs map these to gRPC codes; restorers return
// them so callers can branch on the failure mode.
var (
	ErrUnknownSchemaVersion = errors.New("snapshot: unknown schema version")
	ErrChecksumMismatch     = errors.New("snapshot: checksum mismatch")
	ErrConfirmationRequired = errors.New("snapshot: replace mode requires confirmation token")
	ErrConfirmationMismatch = errors.New("snapshot: confirmation token mismatch")
	ErrUnsupportedRestore   = errors.New("snapshot: backend lacks the capability needed to restore this resource")
	// ErrRollbackWithoutSafety is the SDK validation sentinel for
	// RollbackOnError without an explicit AutoSafetySnapshot net: rollback
	// semantics without an undo artifact would silently degrade to a plain
	// partial apply. The Restorer validates the intent; the orchestration
	// that actually rolls back lives above it.
	ErrRollbackWithoutSafety = errors.New("snapshot: rollback requires an explicit safety snapshot (auto_safety_snapshot=true)")
)

// timeNow is overridable in tests. Production code uses time.Now.
var timeNow = func() time.Time { return time.Now().UTC() }
