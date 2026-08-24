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

	"context"
	"encoding/json"
	"fmt"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// SchemaVersion is the version of the Snapshot envelope. Bump when a
// breaking field change happens; readers refuse unknown versions.
// SchemaVersion is the version of the Snapshot envelope. Bump when a
// breaking field change happens; readers refuse unknown versions.
//
// v2 → v3 adds the two credential-portability categories
// (webauthn_credentials, totp_seeds) to the Resources body. v1/v2
// artifacts stay fully readable by v3 builds; v3 artifacts are refused by
// ≤v2 binaries. Note WHERE the refusal happens in an old binary: the
// JSON codec decodes with DisallowUnknownFields BEFORE the version check
// (codec.go), so a v3 artifact carrying the new fields fails as a JSON
// unknown-field error, and only a new-field-free v3 artifact reaches
// ErrUnknownSchemaVersion. Both fail; the messages differ.
const SchemaVersion = "3"

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
//
// WebAuthnCredentials and SeedEnvelope are the v3 credential-portability
// additions. WebAuthn records are public-key material only (the exporter
// zeroes the attestation blob); SeedEnvelope carries TOTP seeds as opaque
// ciphertext inside a purpose-separated sealed envelope — decrypting the
// body key does NOT decrypt the seeds, and the envelope is only ever
// present when the operator explicitly asked.
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

	// WebAuthnCredentials is the v3 passkey-portability category: one
	// verification-relevant credential projection per enrolled passkey
	// (public key, counter, flags, attestation format — never the
	// attestation blob). Exported only when the wired webauthn.UserStore
	// implements webauthn.CredentialLister; restored only when the
	// restorer has a webauthn.UserStore wired.
	WebAuthnCredentials []webauthn.UserCredentialRecord `json:"webauthn_credentials,omitempty"`

	// SeedEnvelope is the v3 opt-in TOTP-seed category: a
	// purpose-separated sealed envelope (SeedEnvelopePurpose) whose
	// plaintext is the JSON encoding of []authenticators.SeedRecord.
	// Present only when the operator set ExportOptions.IncludeCredentialSeeds
	// AND encryption + a seed-exporter were wired; the artifact never
	// carries seed plaintext anywhere else.
	SeedEnvelope *SeedEnvelope `json:"totp_seeds,omitempty"`
}

// SeedEnvelope is the purpose-separated ciphertext carrying TOTP seeds
// inside an otherwise-plaintext body. It is a per-category dependency of
// the snapshot body key: Decrypting the body does NOT decrypt seeds — the
// envelope's sealer is derived from the master sealer via
// [PurposeSealer.DeriveSealer] with [SeedEnvelopePurpose] as the purpose,
// so cross-purpose ciphertexts cannot be swapped or opened.
type SeedEnvelope struct {
	Algorithm string `json:"algorithm"`
	Params    []byte `json:"params"`
	Cipher    []byte `json:"cipher"`
}

// SeedEnvelopePurpose is the HKDF derivation purpose for the TOTP-seed
// envelope. Deriving a KEY per purpose (rather than an AD tag) means each
// derived sealer mints its own random nonces, so the AES-GCM nonce domain
// stays per-purpose.
const SeedEnvelopePurpose = "snapshot:totp_seeds:v1"

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

	// CategoryWebAuthn is the v3 passkey-portability category
	// (Resources.WebAuthnCredentials).
	CategoryWebAuthn ResourceCategory = "webauthn_credentials"
	// CategoryTotpSeeds is the v3 opt-in TOTP-seed category
	// (Resources.SeedEnvelope).
	CategoryTotpSeeds ResourceCategory = "totp_seeds"
)

// AllCategories is the canonical category list, used for "include all"
// defaulting. Do not mutate the returned slice. The two v3
// credential-portability categories are appended at the END so the
// v1/v2 category order — which artifacts and legacy exclude sets
// depend on — stays byte-identical.
func AllCategories() []ResourceCategory {
	return []ResourceCategory{
		CategoryTenants, CategoryTenantDomains, CategoryConnections,
		CategoryClients, CategoryUsers, CategoryPairwise, CategoryRoles,
		CategoryAssignments, CategoryMenus, CategoryNetPolicy,
		CategoryWebAuthn, CategoryTotpSeeds,
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
// Centralized so the codec, restorer, and admin RPC all agree. v1 and v2
// remain readable (legacyCategories + explicit v2 manifests); v3 is the
// current envelope.
func IsValidSchemaVersion(v string) bool { return v == "1" || v == "2" || v == SchemaVersion }

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

	// ErrSnapshotSeedsRequireEncryption is the fail-closed gate for TOTP
	// seed export/restore: an operator who explicitly asked for seed
	// portability must never get silent absence. Raised when the flag is
	// set but the encryption sealer (or its PurposeSealer derivation, or
	// the store's SeedExporter/SeedImporter) is missing. Maps to
	// failed_precondition on the RPC surface.
	ErrSnapshotSeedsRequireEncryption = errors.New("snapshot: totp seeds require a purpose-separated encryption sealer")

	// ErrSnapshotSeedsWithRedaction is raised by Export when a redaction
	// is effective AND seeds were exported: the Redactor interface cannot
	// return errors and cannot scrub opaque ciphertext, so the pipeline
	// refuses rather than silently dropping the category or shipping
	// seeds in a redacted artifact. Operators choose redaction XOR seeds.
	// Maps to failed_precondition on the RPC surface.
	ErrSnapshotSeedsWithRedaction = errors.New("snapshot: totp seeds cannot be exported with redaction enabled (redaction XOR seeds)")
)

// timeNow is overridable in tests. Production code uses time.Now.
var timeNow = func() time.Time { return time.Now().UTC() }

// exportWebAuthn enumerates the passkey-portability category. The
// optional-store pattern applies: a nil store, an excluded category, or a
// store without webauthn.CredentialLister silently omits the category —
// unlike TOTP seeds there is no operator flag, so absence is the honest
// outcome (the report's absent category IS the observability marker).
func (s *Snapshotter) exportWebAuthn(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	if s.WebAuthn == nil || excluded(CategoryWebAuthn, opts.Exclude) {
		return nil
	}
	lister, ok := s.WebAuthn.(webauthn.CredentialLister)
	if !ok {
		return nil
	}
	records, err := lister.ListCredentials(ctx)
	if err != nil {
		// All-or-nothing, consistent with every other category: a partial
		// passkey set would strand some users' logins after restore.
		return fmt.Errorf("snapshot: webauthn.ListCredentials: %w", err)
	}
	if len(records) == 0 {
		return nil
	}
	snap.Resources.WebAuthnCredentials = records
	snap.markCategory(CategoryWebAuthn)
	return nil
}

// exportTotpSeeds builds the opt-in seed envelope. The gates below are
// deliberate: the flag-unset default is silent absence (byte-identical to
// today), but once the operator sets IncludeCredentialSeeds every missing
// gate fails closed with a hard error — an explicit ask must never degrade
// into silent absence. The plaintext records exist only transiently in
// memory here; they never touch the artifact (only the sealed ciphertext
// does).
func (s *Snapshotter) exportTotpSeeds(ctx context.Context, snap *Snapshot, opts ExportOptions) error {
	if !opts.IncludeCredentialSeeds || excluded(CategoryTotpSeeds, opts.Exclude) {
		return nil
	}
	if s.Sealer == nil {
		return errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("no encryption sealer configured"))
	}
	purpose, ok := s.Sealer.(PurposeSealer)
	if !ok {
		return errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("the configured sealer cannot derive purpose-separated keys"))
	}
	exporter, ok := s.TOTP.(authenticators.SeedExporter)
	if !ok {
		return errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("the totp store cannot enumerate seeds (no SeedExporter)"))
	}
	records, err := exporter.ExportSeeds(ctx)
	if err != nil {
		return fmt.Errorf("snapshot: totp.ExportSeeds: %w", err)
	}
	if len(records) == 0 {
		// Zero enrollments is a legitimate empty set — no envelope, no
		// category, nothing to restore.
		return nil
	}
	plain, err := json.Marshal(records)
	if err != nil {
		return fmt.Errorf("snapshot: totp seeds marshal: %w", err)
	}
	derived, err := purpose.DeriveSealer(SeedEnvelopePurpose)
	if err != nil {
		return errors.Join(ErrSnapshotSeedsRequireEncryption, fmt.Errorf("derive seed sealer: %w", err))
	}
	cipher, params, err := derived.Seal(plain)
	if err != nil {
		return fmt.Errorf("snapshot: totp seeds seal: %w", err)
	}
	snap.Resources.SeedEnvelope = &SeedEnvelope{
		Algorithm: derived.Algorithm(),
		Params:    params,
		Cipher:    cipher,
	}
	snap.markCategory(CategoryTotpSeeds)
	return nil
}

// stageTotpSeeds replays the v3 opt-in seed envelope. Semantics:
//
//   - The envelope is a per-category dependency: it runs after users
//     (import targets must exist as restored identities; seeds for unknown
//     users are inert, so membership is not a hard gate).
//   - RestoreCredentialSeeds UNSET (the default): every other category
//     restores; every user found in the envelope lands on
//     Report.MFAReenrollmentRequired and the category counts them as
//     Skipped — the operator sees the re-enrollment backlog instead of
//     discovering lockouts.
//   - RestoreCredentialSeeds SET: per record, ImportSeed (byte-copy in,
//     byte-identical out — existing TOTP verification passes). The first
//     import error aborts the category via runPlan (fail-closed, never
//     silently half-applied; already-imported records stay, matching the
//     documented partial-apply semantics).
//   - Undecryptable envelope (no sealer / wrong key / tamper): category
//     error + conservatively flag EVERY user from the snapshot's users
//     category — over-flagging beats silent lockout.
//   - Dry-run: identical decisions, zero writes.
func (r *Restorer) stageTotpSeeds(ctx context.Context, snap *Snapshot, opts RestoreOptions, sess *restoreSession) (CategoryCounts, error) {
	var counts CategoryCounts
	if snap.Resources.SeedEnvelope == nil {
		return counts, nil
	}
	records, err := r.openSeedEnvelope(snap)
	if err != nil {
		flagAllUsersForReenrollment(sess, snap)
		return counts, errors.Join(err, errors.New("seed envelope could not be opened; flagging every snapshot user for re-enrollment"))
	}
	if !opts.RestoreCredentialSeeds {
		for _, rec := range records {
			counts.Skipped++
			flagUserForReenrollment(sess, rec.UserID)
		}
		return counts, nil
	}
	importer, ok := r.TOTP.(authenticators.SeedImporter)
	if !ok {
		for _, rec := range records {
			flagUserForReenrollment(sess, rec.UserID)
		}
		return counts, errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("the totp store cannot import seeds (no SeedImporter)"))
	}
	for _, rec := range records {
		if opts.DryRun {
			counts.Inserted++
			continue
		}
		if err := importer.ImportSeed(ctx, rec.UserID, rec.Secret); err != nil {
			return counts, fmt.Errorf("import totp seed for %q: %w", rec.UserID, err)
		}
		counts.Inserted++
	}
	return counts, nil
}
