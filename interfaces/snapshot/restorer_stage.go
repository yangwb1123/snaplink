package snapshot

import (
	"context"
	"errors"
	"fmt"

	gw "github.com/go-webauthn/webauthn/webauthn"
	"github.com/yangwb1123/snaplink/domains/authenticators/webauthn"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/shared/security"
)

// catRunner pairs a category with its restore closure.
type catRunner struct {
	cat ResourceCategory
	run func() (CategoryCounts, error)
}

// reportError appends a per-client (non-aborting) restore error to the
// report. Mirrors runPlan's "%s: %v" error shape so consumers see one
// uniform format.
func (s *restoreSession) reportError(cat ResourceCategory, err error) {
	if s == nil || s.rep == nil {
		return
	}
	s.rep.Errors = append(s.rep.Errors, fmt.Sprintf("%s: %v", cat, err))
}

// runPlan executes a plan's runners in order, recording per-category counts
// into rep and aborting on the first error. Categories the snapshot doesn't
// cover or the caller excluded are skipped entirely (absent from the report,
// matching the pre-split behavior). Phase B prune counts merge into the
// Phase A counts of the same category (prunes only ever produce Deleted);
// RequiresRotation merges the same way so a Phase B runner can never erase
// a Phase A prediction.
func runPlan(ctx context.Context, rep *Report, snap *Snapshot, opts RestoreOptions, plan []catRunner) error {
	for _, p := range plan {
		if excluded(p.cat, opts.Exclude) || !snap.IncludesCategory(p.cat) {
			continue
		}
		c, err := p.run()
		if prev, ok := rep.Items[p.cat]; ok {
			c.Inserted += prev.Inserted
			c.Updated += prev.Updated
			c.Deleted += prev.Deleted
			c.Skipped += prev.Skipped
			c.RequiresRotation += prev.RequiresRotation
		}
		rep.Items[p.cat] = c
		if err != nil {
			rep.Errors = append(rep.Errors, fmt.Sprintf("%s: %v", p.cat, err))
			return fmt.Errorf("snapshot restore: %s: %w", p.cat, err)
		}
	}
	return nil
}

// stagePlan returns the Phase A runners: every category's insert/update/
// upsert in dependency order. Menus are deliberately here: replaceMenus
// wipes via SetMenus's replace semantics per client-roster entry and has no
// separate prune, so the wipe is a stage, not a Phase B prune.
//
// The two v3 credential categories run RIGHT AFTER users: webauthn
// credentials and TOTP seeds both key on restored identities (a passkey
// whose user does not exist as a restored identity is an orphan; a seed
// whose user is absent is inert). The tenant→clients→users prefix order is
// load-bearing and must not be disturbed.
func (r *Restorer) stagePlan(ctx context.Context, snap *Snapshot, opts RestoreOptions, sess *restoreSession) []catRunner {
	return []catRunner{
		{CategoryTenants, func() (CategoryCounts, error) { return r.stageTenants(ctx, snap, opts) }},
		{CategoryTenantDomains, func() (CategoryCounts, error) { return r.stageTenantDomains(ctx, snap, opts) }},
		{CategoryConnections, func() (CategoryCounts, error) { return r.stageConnections(ctx, snap, opts) }},
		{CategoryClients, func() (CategoryCounts, error) { return r.stageClients(ctx, snap, opts, sess) }},
		{CategoryUsers, func() (CategoryCounts, error) { return r.stageUsers(ctx, snap, opts) }},
		{CategoryWebAuthn, func() (CategoryCounts, error) { return r.stageWebAuthn(ctx, snap, opts) }},
		{CategoryTotpSeeds, func() (CategoryCounts, error) { return r.stageTotpSeeds(ctx, snap, opts, sess) }},
		{CategoryPairwise, func() (CategoryCounts, error) { return r.stagePairwise(ctx, snap, opts) }},
		{CategoryRoles, func() (CategoryCounts, error) { return r.stageRoles(ctx, snap, opts) }},
		{CategoryMenus, func() (CategoryCounts, error) { return r.stageMenus(ctx, snap, opts) }},
		{CategoryAssignments, func() (CategoryCounts, error) { return r.stageAssignments(ctx, snap, opts) }},
		{CategoryNetPolicy, func() (CategoryCounts, error) { return r.stageNetPolicy(ctx, snap, opts) }},
	}
}

// prunePlan returns the Phase B runners (ModeReplace only), in the SAME
// category order as stagePlan. The ordering is load-bearing: a strict
// backend may reject deleting a client whose roles/assignments still exist,
// so parent categories prune before their dependents. Menus have no prune.
// Backends that are nil are skipped (the stages skip them too).
func (r *Restorer) prunePlan(ctx context.Context, snap *Snapshot, opts RestoreOptions) []catRunner {
	plan := make([]catRunner, 0, 9)
	add := func(cat ResourceCategory, run func() (CategoryCounts, error)) {
		plan = append(plan, catRunner{cat: cat, run: run})
	}
	if r.Tenants != nil {
		add(CategoryTenants, func() (CategoryCounts, error) {
			return r.pruneTenants(ctx, snap.Resources.Tenants, opts.DryRun)
		})
		add(CategoryTenantDomains, func() (CategoryCounts, error) {
			return r.pruneTenantDomains(ctx, snap.Resources.TenantDomains, opts.DryRun)
		})
	}
	if r.Connections != nil {
		add(CategoryConnections, func() (CategoryCounts, error) {
			return r.pruneConnections(ctx, snap.Resources.Connections, opts.DryRun)
		})
	}
	if r.Clients != nil {
		add(CategoryClients, func() (CategoryCounts, error) {
			return r.pruneClients(ctx, snap, opts.DryRun)
		})
	}
	if r.Users != nil {
		add(CategoryUsers, func() (CategoryCounts, error) {
			return r.pruneUsers(ctx, snap, opts.DryRun)
		})
	}
	if r.Pairwise != nil {
		add(CategoryPairwise, func() (CategoryCounts, error) {
			return r.prunePairwise(ctx, snap.Resources.Pairwise, opts.DryRun)
		})
	}
	if r.Permissions != nil {
		add(CategoryRoles, func() (CategoryCounts, error) {
			return r.pruneRoles(ctx, snap, opts.DryRun)
		})
		add(CategoryAssignments, func() (CategoryCounts, error) {
			return r.pruneAssignments(ctx, snap, opts.DryRun)
		})
	}
	if r.NetPolicy != nil {
		add(CategoryNetPolicy, func() (CategoryCounts, error) {
			return r.pruneNetPolicy(ctx, snap, opts.DryRun)
		})
	}
	return plan
}

// preflightReplace fails before any write when a wired backend lacks a
// capability its ModeReplace prune needs. Only the two capability-gated
// prunes are checked (connections Lister; pairwise Lister + Deleter) — every
// other prune operates on the base store interfaces (verified against the
// per-category restore code). Nil backends are skipped silently by the
// restore, so they don't preflight either. Excluded categories and
// categories the snapshot doesn't cover never prune, so they don't
// preflight. Failure surfaces as ErrUnsupportedRestore (FailedPrecondition
// on the wire) — a caller-side precondition, not a server fault.
func (r *Restorer) preflightReplace(snap *Snapshot, opts RestoreOptions) error {
	for _, cat := range AllCategories() {
		if excluded(cat, opts.Exclude) || !snap.IncludesCategory(cat) {
			continue
		}
		switch cat {
		case CategoryConnections:
			if r.Connections == nil {
				continue
			}
			if _, ok := r.Connections.(connections.Lister); !ok {
				return errors.Join(ErrUnsupportedRestore, errors.New("connections backend cannot list all records"))
			}
		case CategoryPairwise:
			if r.Pairwise == nil {
				continue
			}
			if _, ok := r.Pairwise.(security.PairwiseSubjectLister); !ok {
				return errors.Join(ErrUnsupportedRestore, errors.New("pairwise backend cannot list records"))
			}
			if _, ok := r.Pairwise.(security.PairwiseSubjectDeleter); !ok {
				return errors.Join(ErrUnsupportedRestore, errors.New("pairwise backend cannot delete records"))
			}
		}
	}
	return nil
}

func (r *Restorer) stagePairwise(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var counts CategoryCounts
	if r.Pairwise == nil {
		return counts, nil
	}
	for _, item := range snap.Resources.Pairwise {
		_, err := r.Pairwise.LocalSubject(ctx, item.PairwiseSub)
		exists := err == nil
		if err != nil && !errors.Is(err, security.ErrPairwiseUnknown) {
			return counts, err
		}
		if exists && opts.Mode == ModeMerge {
			counts.Skipped++
			continue
		}
		if exists {
			counts.Updated++
		} else {
			counts.Inserted++
		}
		if !opts.DryRun {
			if err := r.Pairwise.MapPairwise(ctx, item.PairwiseSub, item.LocalSub); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) prunePairwise(ctx context.Context, wanted []security.PairwiseSubjectMapping, dryRun bool) (CategoryCounts, error) {
	var counts CategoryCounts
	lister, listOK := r.Pairwise.(security.PairwiseSubjectLister)
	deleter, deleteOK := r.Pairwise.(security.PairwiseSubjectDeleter)
	if !listOK || !deleteOK {
		return counts, errors.Join(ErrUnsupportedRestore, errors.New("pairwise backend cannot list and delete records"))
	}
	current, err := lister.ListPairwiseSubjects(ctx)
	if err != nil {
		return counts, err
	}
	keep := make(map[string]bool, len(wanted))
	for _, item := range wanted {
		keep[item.PairwiseSub] = true
	}
	for _, item := range current {
		if keep[item.PairwiseSub] {
			continue
		}
		counts.Deleted++
		if !dryRun {
			if err := deleter.DeletePairwiseSubject(ctx, item.PairwiseSub); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) stageTenants(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var counts CategoryCounts
	if r.Tenants == nil {
		return counts, nil
	}
	for _, item := range snap.Resources.Tenants {
		_, err := r.Tenants.GetTenant(ctx, item.ID)
		exists := err == nil
		if err != nil && !errors.Is(err, tenant.ErrTenantNotFound) {
			return counts, err
		}
		if exists && opts.Mode == ModeMerge {
			counts.Skipped++
			continue
		}
		if exists {
			counts.Updated++
		} else {
			counts.Inserted++
		}
		if !opts.DryRun {
			if err := r.Tenants.PutTenant(ctx, item); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) pruneTenants(ctx context.Context, wanted []*tenant.Tenant, dryRun bool) (CategoryCounts, error) {
	var counts CategoryCounts
	current, err := r.Tenants.ListTenants(ctx)
	if err != nil {
		return counts, err
	}
	keep := make(map[string]bool, len(wanted))
	for _, item := range wanted {
		keep[item.ID] = true
	}
	for _, item := range current {
		if keep[item.ID] {
			continue
		}
		counts.Deleted++
		if !dryRun {
			if err := r.Tenants.DeleteTenant(ctx, item.ID); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) stageTenantDomains(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var counts CategoryCounts
	if r.Tenants == nil {
		return counts, nil
	}
	for _, item := range snap.Resources.TenantDomains {
		_, err := r.Tenants.GetDomain(ctx, item.Hostname)
		exists := err == nil
		if err != nil && !errors.Is(err, tenant.ErrDomainNotFound) {
			return counts, err
		}
		if exists && opts.Mode == ModeMerge {
			counts.Skipped++
			continue
		}
		if exists {
			counts.Updated++
		} else {
			counts.Inserted++
		}
		if !opts.DryRun {
			if err := r.Tenants.PutDomain(ctx, item); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) pruneTenantDomains(ctx context.Context, wanted []*tenant.Domain, dryRun bool) (CategoryCounts, error) {
	var counts CategoryCounts
	current, err := r.Tenants.ListDomains(ctx)
	if err != nil {
		return counts, err
	}
	keep := make(map[string]bool, len(wanted))
	for _, item := range wanted {
		keep[item.Hostname] = true
	}
	for _, item := range current {
		if keep[item.Hostname] {
			continue
		}
		counts.Deleted++
		if !dryRun {
			if err := r.Tenants.DeleteDomain(ctx, item.Hostname); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) stageConnections(ctx context.Context, snap *Snapshot, opts RestoreOptions) (CategoryCounts, error) {
	var counts CategoryCounts
	if r.Connections == nil {
		return counts, nil
	}
	for _, item := range snap.Resources.Connections {
		_, err := r.Connections.Get(ctx, item.ID)
		exists := err == nil
		if err != nil && !errors.Is(err, connections.ErrNoConnection) {
			return counts, err
		}
		if exists && opts.Mode == ModeMerge {
			counts.Skipped++
			continue
		}
		if exists {
			counts.Updated++
		} else {
			counts.Inserted++
		}
		if !opts.DryRun {
			if err := r.Connections.Upsert(ctx, item); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

func (r *Restorer) pruneConnections(ctx context.Context, wanted []*connections.Connection, dryRun bool) (CategoryCounts, error) {
	var counts CategoryCounts
	lister, ok := r.Connections.(connections.Lister)
	if !ok {
		return counts, errors.Join(ErrUnsupportedRestore, errors.New("connections backend cannot list all records"))
	}
	current, err := lister.List(ctx)
	if err != nil {
		return counts, err
	}
	keep := make(map[string]bool, len(wanted))
	for _, item := range wanted {
		keep[item.ID] = true
	}
	for _, item := range current {
		if keep[item.ID] {
			continue
		}
		counts.Deleted++
		if !dryRun {
			if err := r.Connections.Delete(ctx, item.ID); err != nil {
				return counts, err
			}
		}
	}
	return counts, nil
}

// errNoSnapshotter / errNoPipelineStorage are defensive guards for
// SDK-direct CaptureSafetySnapshot callers. The admin orchestrator performs
// the same nil-snapshotter check BEFORE operations.Start (zero writes);
// these only fire when a caller bypasses the orchestration.
var (
	errNoSnapshotter     = errors.New("snapshot: safety capture requires a configured snapshotter")
	errNoPipelineStorage = errors.New("snapshot: safety capture requires a pipeline and storage")
)

// CaptureSafetySnapshot exports the destination node's current state and
// persists it as a safety-kind envelope — the undo artifact a replace
// restore (and its rollback) relies on. It is the D1 capture step:
//
//   - The explicit no-op Redactor override beats Snapshotter.DefaultExportRedactor
//     (effectiveRedactor precedence), so the artifact stays RESTORABLE even
//     when snapshot.redact_secrets=true is wired — a redacted safety
//     snapshot could not restore credentials and would silently defeat the
//     net. The no-op override is pinned by a test.
//   - The snapshot is marked KindSafetySnapshot; Pipeline.Save mirrors the
//     kind into the SealedEnvelope header, which is what retention skips
//     and List/Get render without decryption.
//   - The artifact lives in the same Storage as ordinary exports (snap_
//     prefix) and is removed by the explicit Delete RPC; retention never
//     prunes safety-kind envelopes.
//
// Capture is NOT atomic: Export lists stores sequentially, so a concurrent
// write can produce a state that never existed. Restore is documented for
// maintenance windows; the same caveat applies to the net.
func CaptureSafetySnapshot(ctx context.Context, s *Snapshotter, p *Pipeline, dst Storage) (*Snapshot, error) {
	if s == nil {
		return nil, errNoSnapshotter
	}
	if p == nil || dst == nil {
		return nil, errNoPipelineStorage
	}
	snap, err := s.Export(ctx, ExportOptions{
		Redactor: RedactorFunc(func(*Snapshot) {}),
	})
	if err != nil {
		return nil, err
	}
	snap.Kind = KindSafetySnapshot
	if err := p.Save(ctx, snap, dst, snap.SnapshotID); err != nil {
		return nil, err
	}
	return snap, nil
}

// RollbackExcludeFor computes the category exclusion set for a rollback
// re-apply: the failed restore's original excludes PLUS every category the
// failed restore's SOURCE snapshot did not cover. The rollback then touches
// exactly the categories the failed restore could have mutated — it never
// rewinds categories the restore never touched (e.g. a netpolicy category
// the operator excluded as environment-specific, or a backend that was
// unwired at export time). Returns a fresh slice; the input is not mutated.
func RollbackExcludeFor(src *Snapshot, originalExclude []ResourceCategory) []ResourceCategory {
	out := append([]ResourceCategory(nil), originalExclude...)
	for _, cat := range AllCategories() {
		if !src.IncludesCategory(cat) && !excluded(cat, out) {
			out = append(out, cat)
		}
	}
	return out
}

// replayCredentialExtensions persists the record's SDK-captured extension
// metadata when the store supports it; an absent capability leaves the
// extensions nil ("unknown") — the documented safe default. A setter error
// aborts the category like any other replay error (fail-closed).
func replayCredentialExtensions(ctx context.Context, extSetter webauthn.CredentialExtensionSetter, rec webauthn.UserCredentialRecord, cred *gw.Credential) error {
	if extSetter == nil || !extensionsPresent(rec.Extensions) {
		return nil
	}
	if err := extSetter.SetCredentialExtensions(ctx, rec.UserName, cred.ID, rec.Extensions); err != nil {
		return fmt.Errorf("set webauthn extensions for %q: %w", rec.UserName, err)
	}
	return nil
}
