package snapshot

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"encoding/json"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/shared/security"
)

// RestoreMode is how a Restorer treats existing destination state.
//
//   - ModeMerge: insert items that don't exist; leave existing untouched.
//     Safest mode — operators bringing a peer node up to a baseline use this.
//   - ModeOverwrite: insert when missing, update when present. No deletion.
//     Useful when the snapshot is the new source of truth for matching IDs
//     but the destination has extra resources you want to preserve.
//   - ModeReplace: wipe the destination categories the snapshot covers, then
//     insert everything from the snapshot. Strictly the most dangerous —
//     the Restorer requires a Confirm token equal to the SnapshotID.
type RestoreMode string

const (
	ModeMerge     RestoreMode = "merge"
	ModeOverwrite RestoreMode = "overwrite"
	ModeReplace   RestoreMode = "replace"
)

// Restorer applies a Snapshot to a destination. Every backend field is
// optional in the same shape as Snapshotter — categories whose backend is
// nil are silently skipped on restore.
//
// WebAuthn / TOTP / Sealer are the v3 credential-portability seams: all
// optional, all type-asserted at use time (never required by the base
// store interfaces). Nil WebAuthn silently skips the webauthn category;
// nil TOTP/Sealer still reports the re-enrollment backlog for an artifact
// that carries seeds (see [Report.MFAReenrollmentRequired]).
type Restorer struct {
	Clients     sso.ClientStore               // optional
	Users       sso.UserProvider              // optional
	Permissions permissions.Provider          // optional
	NetPolicy   netpolicy.Store               // optional
	Tenants     tenant.Store                  // optional
	Connections connections.Store             // optional
	Pairwise    security.PairwiseSubjectStore // optional
	Invalidator RestoreInvalidator            // optional
	Tracker     bootstrap.Tracker             // optional, for AdvanceBootstrap
	Namespace   string                        // bootstrap namespace; defaults to snapshot's

	// WebAuthn is the passkey store replayed by the webauthn_credentials
	// category. Nil ⇒ the category is silently skipped on restore.
	WebAuthn webauthn.UserStore

	// TOTP is the seed store for the totp_seeds category, and Sealer the
	// master encryption sealer whose purpose-derivation opens the seed
	// envelope. Both optional; a missing Sealer on an opted-in restore is
	// a reported category error (never a silent skip — operators must see
	// the re-enrollment backlog).
	TOTP   authenticators.TOTPStore
	Sealer Sealer
}

// SecretRotator is the optional capability the Restorer uses to
// regenerate secrets for clients that a fresh-node restore left
// secret-less. Structurally satisfied by every sso.ClientStore (the base
// interface already carries RotateSecret); declared separately so the
// restorer's dependency is explicit and a future base-interface shrink
// cannot silently break the recovery path.
type SecretRotator interface {
	RotateSecret(ctx context.Context, clientID string) (string, error)
}

// RestoreInvalidator flushes local and peer control-plane caches after a
// successful non-dry-run restore.
type RestoreInvalidator interface {
	InvalidateRestoredControlPlane()
}

// RestoreOptions tunes a single Restore call.
type RestoreOptions struct {
	Mode             RestoreMode
	DryRun           bool
	Exclude          []ResourceCategory
	AdvanceBootstrap bool

	// RestoreCredentialSeeds opts into replaying the artifact's TOTP seed
	// envelope (totp_seeds category) into the wired TOTP store. Unset (the
	// default) restores every other category and flags every user found in
	// the envelope on [Report.MFAReenrollmentRequired] so lockouts are
	// discovered from the report, not by users.
	RestoreCredentialSeeds bool

	// Confirm is REQUIRED for ModeReplace. Operators must echo back the
	// snapshot's SnapshotID — a dumb "yes I know what I'm doing" knob that
	// makes accidental wipes hard. Ignored for Merge and Overwrite.
	Confirm string

	// AutoSafetySnapshot and RollbackOnError are ORCHESTRATOR intents:
	// the Restorer itself never captures a safety snapshot and never rolls
	// back (it has no Pipeline/Storage). The orchestrator (grpcadmin
	// restoreTracked) consumes them to decide capture + rollback behavior
	// and passes them through so SDK-direct callers get the same
	// validation. AutoSafetySnapshot is the normalized intent (explicit
	// true, or defaulted by the orchestrator for replace non-dry-runs);
	// RollbackOnError requires AutoSafetySnapshot=true or prepareRestore
	// rejects the call with ErrRollbackWithoutSafety before any write.
	AutoSafetySnapshot bool
	RollbackOnError    bool

	// Preview attaches the entry-level snapshot-vs-live diff to the
	// report on a NON-dry-run restore (dry-run always attaches it). The
	// preview is computed before any write and fails closed on
	// enumeration errors. Default false — existing callers see zero
	// behavior change (Report.Diff stays nil).
	Preview bool
}

// Report is the per-category outcome of a restore. Counts are accumulated
// across the run; a non-nil Errors slice means at least one category bailed
// (other categories may still have applied — see Restore) OR a per-client
// secret-rotation step failed (those are recorded as errors but never abort
// the plan). Counts are meaningful only when Committed is true (or the run
// returned no error): on a Phase B failure the Deleted counts are partial
// while Inserted / Updated are complete.
type Report struct {
	Mode      RestoreMode
	DryRun    bool
	Items     map[ResourceCategory]CategoryCounts
	Bootstrap BootstrapAdvance
	Errors    []string

	// CredentialRecovery names one client whose secret was regenerated by
	// this restore, plus the new plaintext. The secret is an
	// RPC-response-only value: audit and operations records must carry
	// client IDs, never the secret (admin_clients.go "secrets are never
	// echoed") — persist via [RedactCredentialRecovery], never the raw
	// Report. Populated only on non-dry-run restores.
	CredentialRecovery []CredentialRecovery `json:"credential_recovery,omitempty"`

	// MFAReenrollmentRequired lists user IDs whose TOTP enrollment could
	// not be restored (opt-out, undecryptable envelope, or import failure)
	// and therefore need operator-driven re-enrollment. On an
	// undecryptable envelope the list conservatively covers every user in
	// the snapshot's users category (over-flagging beats silent lockout).
	MFAReenrollmentRequired []string `json:"mfa_reenrollment_required,omitempty"`

	// Committed is true iff a non-dry-run restore completed every phase
	// without error. Dry-run always reports false (predictions, not
	// writes). A bootstrap-advance failure AFTER the phases applied leaves
	// Committed true (data is applied; only the tracker didn't advance) —
	// callers must not key on err alone.
	Committed bool
	// RolledBack and SafetySnapshotID are set by the ORCHESTRATOR on the
	// rollback path (the Restorer never orchestrates). RolledBack reports
	// that the failed restore's safety snapshot was re-applied;
	// SafetySnapshotID names the undo artifact (also echoed on the success
	// path when a capture ran).
	RolledBack       bool
	SafetySnapshotID string

	// Diff is the entry-level snapshot-vs-live preview, computed when
	// opts.DryRun or opts.Preview. json:"preview,omitempty" keeps every
	// legacy ResultJSON byte identical when no preview ran. Dry-run
	// counts of diff-covered categories are projected from this diff;
	// uncovered categories keep the plan's probe/optimistic counts.
	Diff *DiffResult `json:"preview,omitempty"`
}

// CredentialRecovery is one rotated client secret from Decision 1's
// fresh-node regeneration. Secret is deliberately exported (the RPC
// response is the ONLY sanctioned recovery channel); every persisted
// representation must strip it via [RedactCredentialRecovery].
type CredentialRecovery struct {
	ClientID string `json:"client_id"`
	Secret   string `json:"secret"`
}

// RedactCredentialRecovery returns a copy of rep whose
// CredentialRecovery entries carry client IDs only — the plaintext
// rotated secrets are dropped. The RPC response keeps them (they are the
// recovery channel); every PERSISTED representation (operations
// ResultJSON, audit payloads) must pass through this so rotated secrets
// never land in durable records.
func RedactCredentialRecovery(rep *Report) *Report {
	if rep == nil || len(rep.CredentialRecovery) == 0 {
		return rep
	}
	out := *rep
	out.CredentialRecovery = make([]CredentialRecovery, len(rep.CredentialRecovery))
	for i, c := range rep.CredentialRecovery {
		out.CredentialRecovery[i] = CredentialRecovery{ClientID: c.ClientID}
	}
	return &out
}

// CategoryCounts is the per-resource bookkeeping the Report carries.
// Unchanged counts entries whose content already matches the snapshot —
// the no-op distinction dry-run previously could not make (presence alone
// was counted as Updated). It is only meaningful on dry-run reports (and
// the preview overlay); the apply path never writes an unchanged entry.
//
// RequiresRotation is the count of clients this restore left in a state
// where a usable client secret is missing: active secret-auth clients
// whose rotation did not run (store lacks [SecretRotator]) or failed, plus
// INACTIVE secret-auth clients (the Active gate skips their rotation, but
// the operator must rotate before enabling — flag-on-enable, never
// silently skipped). Dry-run predicts the exact set the real run would
// leave; public and federation clients are never counted (they carry no
// secret by design).
type CategoryCounts struct {
	Inserted  int
	Updated   int
	Deleted   int
	Skipped   int
	Unchanged int

	// RequiresRotation counts clients needing a usable secret (see type
	// doc). Rotation successes are NOT counted (they were remediated);
	// the successful rotations surface as [Report.CredentialRecovery]
	// entries instead.
	RequiresRotation int
}

// BootstrapAdvance describes what happened to the destination Tracker.
type BootstrapAdvance struct {
	Attempted bool
	From      int
	To        int
	NoOp      bool   // true when From >= To (snapshot is older or same)
	Reason    string // populated when Attempted but skipped
}

// Restore applies snap onto the destination per opts. Returns a Report
// regardless of error so callers can see partial work; the error (when
// non-nil) is the first hard failure that aborted the run.
//
// ModeReplace runs in TWO phases (see restorer_stage.go): Phase A stages
// every category's insert/update/upsert in dependency order with all prunes
// disabled; Phase B, only after Phase A fully succeeds, runs every
// category's prune in the same order. A mid-plan failure therefore leaves
// either an old-state superset (Phase A fail — nothing deleted, retry-safe)
// or a target-state superset (Phase B fail — partial deletes, same-snapshot
// retry converges). Merge/overwrite run Phase A only, exactly as before.
func (r *Restorer) Restore(ctx context.Context, snap *Snapshot, opts RestoreOptions) (*Report, error) {
	if err := r.prepareRestore(snap, &opts); err != nil {
		return nil, err
	}
	rep := &Report{
		Mode:   opts.Mode,
		DryRun: opts.DryRun,
		Items:  make(map[ResourceCategory]CategoryCounts, len(AllCategories())),
	}
	if err := r.attachRestorePreview(ctx, snap, opts, rep); err != nil {
		return nil, err
	}
	sess := &restoreSession{writtenClients: make(map[string]bool)}
	if err := r.applyRestorePlans(ctx, snap, opts, rep, sess); err != nil {
		return rep, err
	}
	rep.Committed = !opts.DryRun
	if err := r.advanceRestoreBootstrap(ctx, snap, opts, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func (r *Restorer) attachRestorePreview(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report) error {
	if !opts.DryRun && !opts.Preview {
		return nil
	}
	diff, err := r.Preview(ctx, snap, opts)
	if err == nil {
		rep.Diff = diff
	}
	return err
}

// restoreSession carries per-RESTORE bookkeeping down the stage call
// chain. Allocated by Restore and passed by parameter — the shared
// Restorer stays stateless between calls. The write-set is the Decision-1
// "written by this restore" guard: Merge must never rotate a
// pre-existing destination client, so eligibility keys on this set, not
// on live state alone.
type restoreSession struct {
	writtenClients map[string]bool
	rep            *Report
}

func (r *Restorer) applyRestorePlans(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report, sess *restoreSession) error {
	sess.rep = rep
	if err := runPlan(ctx, rep, snap, opts, r.stagePlan(ctx, snap, opts, sess)); err != nil {
		return err
	}
	if opts.Mode == ModeReplace {
		if err := runPlan(ctx, rep, snap, opts, r.prunePlan(ctx, snap, opts)); err != nil {
			return err
		}
	}
	if !opts.DryRun && r.Invalidator != nil {
		r.Invalidator.InvalidateRestoredControlPlane()
	}
	if opts.DryRun {
		overlayDryRunCounts(rep, opts.Mode, rep.Diff)
	}
	return nil
}

func (r *Restorer) advanceRestoreBootstrap(ctx context.Context, snap *Snapshot, opts RestoreOptions, rep *Report) error {
	if !opts.AdvanceBootstrap {
		return nil
	}
	advance, err := r.advanceBootstrap(ctx, snap, opts.DryRun)
	rep.Bootstrap = advance
	if err != nil {
		rep.Errors = append(rep.Errors, "bootstrap: "+err.Error())
		return fmt.Errorf("snapshot restore: bootstrap advance: %w", err)
	}
	return nil
}

// ValidateRestore runs prepareRestore's checks (snapshot validity, mode
// defaulting, the ModeReplace confirmation handshake, capability preflight,
// and the rollback-requires-a-net rule) WITHOUT applying anything. The admin
// orchestrator calls it after load and BEFORE the D1 safety capture so an
// invalid request never writes — not even the undo artifact; Restore itself
// re-runs the same checks, so SDK-direct callers are equally protected.
// opts is normalized in place exactly as Restore would.
func (r *Restorer) ValidateRestore(snap *Snapshot, opts *RestoreOptions) error {
	return r.prepareRestore(snap, opts)
}

// prepareRestore validates the snapshot and normalizes opts in place:
// defaulting an empty Mode to Merge and enforcing the ModeReplace
// confirmation handshake. It also fails before any write when the caller
// requested rollback without an explicit safety net — the validation reads
// the caller's RAW AutoSafetySnapshot (the Restorer never defaults it; the
// orchestrator does) so the strict "rollback requires an explicit net"
// contract cannot be bypassed by defaulting.
func (r *Restorer) prepareRestore(snap *Snapshot, opts *RestoreOptions) error {
	if snap == nil {
		return errors.New("snapshot: nil snapshot")
	}
	if err := snap.Validate(); err != nil {
		return err
	}
	if opts.Mode == "" {
		opts.Mode = ModeMerge
	}
	if opts.Mode == ModeReplace {
		if opts.Confirm == "" {
			return ErrConfirmationRequired
		}
		if opts.Confirm != snap.SnapshotID {
			return ErrConfirmationMismatch
		}
		// Capability preflight: fail before any write (including the
		// operations ledger) when a wired backend lacks a capability its
		// ModeReplace prune needs.
		if err := r.preflightReplace(snap, *opts); err != nil {
			return err
		}
	}
	if opts.RollbackOnError && !opts.AutoSafetySnapshot {
		return ErrRollbackWithoutSafety
	}
	return nil
}

// advanceBootstrap bumps the destination Tracker's recorded "highest
// applied" to match the snapshot's, but only when the snapshot is *newer*.
// Useful when restoring on a fresh node so seed steps don't re-run on top
// of imported data.
func (r *Restorer) advanceBootstrap(ctx context.Context, snap *Snapshot, dryRun bool) (BootstrapAdvance, error) {
	out := BootstrapAdvance{Attempted: true}
	if r.Tracker == nil {
		out.Reason = "tracker not configured"
		out.NoOp = true
		return out, nil
	}
	ns := r.Namespace
	if ns == "" {
		ns = snap.BootstrapState.Namespace
	}
	if ns == "" {
		out.Reason = "no namespace"
		out.NoOp = true
		return out, nil
	}
	cur, err := r.Tracker.AppliedVersion(ctx, ns)
	if err != nil {
		return out, fmt.Errorf("read applied version: %w", err)
	}
	out.From = cur
	out.To = snap.BootstrapState.AppliedVersion
	if out.To <= cur {
		out.NoOp = true
		out.Reason = "snapshot version not newer"
		return out, nil
	}
	if dryRun {
		return out, nil
	}
	if err := r.Tracker.MarkApplied(ctx, ns, out.To, "snapshot_restore"); err != nil {
		return out, fmt.Errorf("mark applied: %w", err)
	}
	return out, nil
}

// appendUnique adds s to dst iff it is not already present. O(n) — fine
// for the small role-code lists snapshots carry.
func appendUnique(dst []string, s string) []string {
	if slices.Contains(dst, s) {
		return dst
	}
	return append(dst, s)
}

// openSeedEnvelope opens and decodes the artifact's seed envelope with a
// purpose-derived sealer. Failures are deliberately indistinguishable in
// kind (wrong key, tamper, missing sealer) — the caller's conservative
// all-users flag covers them all.
func (r *Restorer) openSeedEnvelope(snap *Snapshot) ([]authenticators.SeedRecord, error) {
	env := snap.Resources.SeedEnvelope
	if r.Sealer == nil {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("no sealer configured"))
	}
	purpose, ok := r.Sealer.(PurposeSealer)
	if !ok {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("the configured sealer cannot derive purpose-separated keys"))
	}
	if env.Algorithm != r.Sealer.Algorithm() {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, errors.New("seed envelope algorithm does not match the configured sealer"))
	}
	derived, err := purpose.DeriveSealer(SeedEnvelopePurpose)
	if err != nil {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, fmt.Errorf("derive seed sealer: %w", err))
	}
	plain, err := derived.Open(env.Cipher, env.Params)
	if err != nil {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, fmt.Errorf("open seed envelope: %w", err))
	}
	var records []authenticators.SeedRecord
	if err := json.Unmarshal(plain, &records); err != nil {
		return nil, errors.Join(ErrSnapshotSeedsRequireEncryption, fmt.Errorf("decode seed envelope: %w", err))
	}
	return records, nil
}

// flagUserForReenrollment appends one user ID to the report's
// re-enrollment backlog, deduplicated.
func flagUserForReenrollment(sess *restoreSession, userID string) {
	if sess == nil || sess.rep == nil || userID == "" {
		return
	}
	// Small slice; linear scan is fine (enrollment counts are bounded).
	for _, existing := range sess.rep.MFAReenrollmentRequired {
		if existing == userID {
			return
		}
	}
	sess.rep.MFAReenrollmentRequired = append(sess.rep.MFAReenrollmentRequired, userID)
}

// flagAllUsersForReenrollment conservatively flags every user the
// snapshot's users category carries — the undecryptable-envelope fallback
// (over-flagging beats silent lockout).
func flagAllUsersForReenrollment(sess *restoreSession, snap *Snapshot) {
	for _, u := range snap.Resources.Users {
		if u != nil {
			flagUserForReenrollment(sess, u.ID)
		}
	}
}
