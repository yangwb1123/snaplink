package snapshot_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap/memory"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	netmemory "github.com/yangwb1123/snaplink/platform/netpolicy/memory"
)

// newBlank builds an empty destination wired the same way fixtureBlank is,
// so the restore mode tests below all share one construction path.
func newBlank() *fixtureBlank {
	return &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
}

// TestRestore_Merge_AllPermissionCategories drives the merge-insert paths
// for roles, menus, assignments, and netpolicy into a fresh destination —
// the per-category Inserted counts that the existing merge test (which only
// asserted clients/users/netpolicy) leaves uncovered.
func TestRestore_Merge_AllPermissionCategories(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := newBlank()
	// Clients must exist before roles/menus/assignments are meaningful;
	// they ride in on the same restore, applied in dependency order.
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	// 3 role definitions across 2 client bundles (alpha: admin+viewer, beta: writer).
	if got := rep.Items[snapshot.CategoryRoles].Inserted; got != 3 {
		t.Errorf("roles inserted=%d want 3", got)
	}
	if got := rep.Items[snapshot.CategoryMenus].Inserted; got != 1 {
		t.Errorf("menus inserted=%d want 1", got)
	}
	// 2 assignments (u1->alpha, u2->beta).
	if got := rep.Items[snapshot.CategoryAssignments].Inserted; got != 2 {
		t.Errorf("assignments inserted=%d want 2", got)
	}
	if got := rep.Items[snapshot.CategoryNetPolicy].Inserted; got != 1 {
		t.Errorf("netpolicy inserted=%d want 1", got)
	}

	// Verify the data actually landed.
	roles, _ := dst.perms.ListAllRoles(ctx, "alpha")
	if len(roles) != 2 {
		t.Errorf("alpha roles=%d want 2", len(roles))
	}
	menus, _ := dst.perms.GetMenus(ctx, "alpha")
	if len(menus) != 1 {
		t.Errorf("alpha menus=%d want 1", len(menus))
	}
}

// TestRestore_Merge_SkipsExistingPermissions pre-seeds the destination with
// the same roles/menus/assignments/netpolicy so the merge SKIP branches in
// restoreRoles/restoreMenus/restoreAssignments/restoreNetPolicy all fire.
func TestRestore_Merge_SkipsExistingPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	// Build a destination that already mirrors the source state.
	dst := newBlank()
	mustAdd := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("preseed: %v", err)
		}
	}
	mustAdd(dst.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha"}))
	mustAdd(dst.clients.Add(ctx, &sso.Client{ID: "beta", Name: "Beta"}))
	mustAdd(dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin", Permissions: []string{"a:*"}}))
	mustAdd(dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "viewer", Permissions: []string{"a:read"}}))
	mustAdd(dst.perms.AddRole(ctx, "beta", permissions.Role{Code: "writer", Permissions: []string{"b:write"}}))
	mustAdd(dst.perms.SetMenus(ctx, "alpha", permissions.MenuTree{{ID: "m1", Name: "Dashboards", Path: "/d", Permission: "a:read"}}))
	mustAdd(dst.perms.AssignRoles(ctx, "u1", "alpha", []string{"admin"}))
	mustAdd(dst.perms.AssignRoles(ctx, "u2", "beta", []string{"writer"}))
	if _, err := dst.netpol.Apply(ctx, &netpolicy.Policy{Name: "internal", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("preseed netpol: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}

	// Roles: all 3 already present → all skipped.
	if got := rep.Items[snapshot.CategoryRoles].Skipped; got != 3 {
		t.Errorf("roles skipped=%d want 3 (%+v)", got, rep.Items[snapshot.CategoryRoles])
	}
	// Menus: existing tree present → skipped.
	if got := rep.Items[snapshot.CategoryMenus].Skipped; got != 1 {
		t.Errorf("menus skipped=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryMenus])
	}
	// Assignments: identical role sets already assigned → skipped.
	if got := rep.Items[snapshot.CategoryAssignments].Skipped; got != 2 {
		t.Errorf("assignments skipped=%d want 2 (%+v)", got, rep.Items[snapshot.CategoryAssignments])
	}
	// NetPolicy: same name present → skipped.
	if got := rep.Items[snapshot.CategoryNetPolicy].Skipped; got != 1 {
		t.Errorf("netpolicy skipped=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryNetPolicy])
	}
}

// TestRestore_Merge_AssignmentsUnionExisting exercises the union branch in
// restoreAssignments: the destination user already holds a role NOT in the
// snapshot, and the snapshot adds a new one. The merge must union them and
// report Updated (not Skipped, not Inserted).
func TestRestore_Merge_AssignmentsUnionExisting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	if err := dst.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	// alpha needs the roles to exist before assignment.
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin"})
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "extra"})
	// u1 already holds "extra" — snapshot will add "admin".
	if err := dst.perms.AssignRoles(ctx, "u1", "alpha", []string{"extra"}); err != nil {
		t.Fatalf("preseed assign: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryAssignments].Updated; got < 1 {
		t.Errorf("assignments updated=%d want >=1 (union branch) (%+v)", got, rep.Items[snapshot.CategoryAssignments])
	}
	// The union must preserve "extra" AND add "admin".
	roles, err := dst.perms.Roles(ctx, "u1", "alpha")
	if err != nil {
		t.Fatalf("roles: %v", err)
	}
	have := map[string]bool{}
	for _, r := range roles {
		have[r.Code] = true
	}
	if !have["extra"] || !have["admin"] {
		t.Errorf("union failed: u1 alpha roles=%v want both extra+admin", roles)
	}
}

// TestRestore_Overwrite_UpdatesPermissions drives the overwrite UPDATE paths
// for roles, menus, and assignments — present-then-replace bookkeeping that
// the clients-only overwrite test does not reach.
func TestRestore_Overwrite_UpdatesPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	if err := dst.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	if err := dst.clients.Add(ctx, &sso.Client{ID: "beta", Name: "Beta"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	// Stale role with the same code but different permissions → must update.
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin", Permissions: []string{"stale"}})
	// Stale menu present → must update.
	_ = dst.perms.SetMenus(ctx, "alpha", permissions.MenuTree{{ID: "old", Name: "Old", Path: "/old"}})
	// Existing assignment present → overwrite to snapshot's set.
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin2"})
	_ = dst.perms.AssignRoles(ctx, "u1", "alpha", []string{"admin2"})
	// netpolicy stale → overwrite update.
	if _, err := dst.netpol.Apply(ctx, &netpolicy.Policy{Name: "internal", CIDRs: []string{"192.168.0.0/16"}}); err != nil {
		t.Fatalf("preseed netpol: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryRoles].Updated; got < 1 {
		t.Errorf("roles updated=%d want >=1 (%+v)", got, rep.Items[snapshot.CategoryRoles])
	}
	if got := rep.Items[snapshot.CategoryMenus].Updated; got != 1 {
		t.Errorf("menus updated=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryMenus])
	}
	if got := rep.Items[snapshot.CategoryAssignments].Updated; got < 1 {
		t.Errorf("assignments updated=%d want >=1 (%+v)", got, rep.Items[snapshot.CategoryAssignments])
	}
	if got := rep.Items[snapshot.CategoryNetPolicy].Updated; got != 1 {
		t.Errorf("netpolicy updated=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryNetPolicy])
	}

	// The admin role permissions must now reflect the snapshot, not "stale".
	roles, _ := dst.perms.ListAllRoles(ctx, "alpha")
	for _, r := range roles {
		if r.Code == "admin" {
			for _, p := range r.Permissions {
				if p == "stale" {
					t.Errorf("admin role still carries stale permission after overwrite")
				}
			}
		}
	}
	// netpolicy must now carry the snapshot CIDR.
	got, _ := dst.netpol.Get(ctx, "internal")
	if got == nil || len(got.CIDRs) == 0 || got.CIDRs[0] != "10.0.0.0/8" {
		t.Errorf("netpolicy not overwritten: %+v", got)
	}
}

// TestRestore_Replace_DeletesOrphanPermissions exercises the Replace
// delete-orphan branches for roles, menus, assignments, and netpolicy —
// the destructive paths only partially covered by the clients/users
// orphan test.
func TestRestore_Replace_DeletesOrphanPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	// Mirror the snapshot's clients so they survive replace, plus extras.
	_ = dst.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha"})
	_ = dst.clients.Add(ctx, &sso.Client{ID: "beta", Name: "Beta"})
	// Roles: keep the snapshot ones but add an orphan role under alpha.
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin"})
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "viewer"})
	_ = dst.perms.AddRole(ctx, "alpha", permissions.Role{Code: "orphan-role"})
	_ = dst.perms.AddRole(ctx, "beta", permissions.Role{Code: "writer"})
	// Assignments: u1->alpha matches snapshot; add an orphan user assignment.
	_ = dst.perms.AssignRoles(ctx, "u1", "alpha", []string{"admin"})
	_ = dst.perms.AssignRoles(ctx, "orphan-user", "alpha", []string{"admin"})
	// NetPolicy: keep "internal", add an orphan.
	if _, err := dst.netpol.Apply(ctx, &netpolicy.Policy{Name: "internal", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("netpol: %v", err)
	}
	if _, err := dst.netpol.Apply(ctx, &netpolicy.Policy{Name: "orphan-net", CIDRs: []string{"172.16.0.0/12"}}); err != nil {
		t.Fatalf("netpol: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if got := rep.Items[snapshot.CategoryRoles].Deleted; got != 1 {
		t.Errorf("roles deleted=%d want 1 (orphan-role) (%+v)", got, rep.Items[snapshot.CategoryRoles])
	}
	if got := rep.Items[snapshot.CategoryAssignments].Deleted; got != 1 {
		t.Errorf("assignments deleted=%d want 1 (orphan-user) (%+v)", got, rep.Items[snapshot.CategoryAssignments])
	}
	if got := rep.Items[snapshot.CategoryNetPolicy].Deleted; got != 1 {
		t.Errorf("netpolicy deleted=%d want 1 (orphan-net) (%+v)", got, rep.Items[snapshot.CategoryNetPolicy])
	}

	// Confirm the orphans are gone and the snapshot ones survive.
	roles, _ := dst.perms.ListAllRoles(ctx, "alpha")
	for _, r := range roles {
		if r.Code == "orphan-role" {
			t.Errorf("orphan-role survived replace")
		}
	}
	if _, err := dst.netpol.Get(ctx, "orphan-net"); err == nil {
		t.Errorf("orphan-net policy survived replace")
	}
	if _, err := dst.netpol.Get(ctx, "internal"); err != nil {
		t.Errorf("internal policy was wrongly deleted: %v", err)
	}
}

// TestRestore_Replace_DryRun_NoMutation proves Replace dry-run reports the
// destructive + insert work but mutates nothing — the dry-run guards inside
// every replace branch (the riskiest mode to leave untested).
func TestRestore_Replace_DryRun_NoMutation(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	_ = dst.clients.Add(ctx, &sso.Client{ID: "orphan", Name: "Orphan"})
	_ = dst.users.CreateOrUpdate(ctx, &sso.User{ID: "orphan-user"})

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID, DryRun: true,
	})
	if err != nil {
		t.Fatalf("dry-run replace: %v", err)
	}
	if !rep.DryRun {
		t.Errorf("DryRun not propagated")
	}
	// Counts must still be reported.
	if rep.Items[snapshot.CategoryClients].Deleted != 1 {
		t.Errorf("dry-run replace should report 1 client deleted: %+v", rep.Items[snapshot.CategoryClients])
	}
	// But the destination must be untouched: orphan still present, snapshot
	// clients NOT inserted.
	if _, err := dst.clients.Get(ctx, "orphan"); err != nil {
		t.Errorf("dry-run deleted orphan client: %v", err)
	}
	if _, err := dst.clients.Get(ctx, "alpha"); err == nil {
		t.Errorf("dry-run inserted snapshot client alpha")
	}
}

// TestRestore_Overwrite_DryRun proves overwrite dry-run reports Inserted /
// Updated counts (the dry-run pre-Get probe branches) without mutating.
func TestRestore_Overwrite_DryRun(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	_ = dst.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Stale"})

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite, DryRun: true})
	if err != nil {
		t.Fatalf("dry-run overwrite: %v", err)
	}
	// alpha exists → Updated; beta missing → Inserted.
	cc := rep.Items[snapshot.CategoryClients]
	if cc.Updated != 1 || cc.Inserted != 1 {
		t.Errorf("overwrite dry-run client counts = %+v, want Updated=1 Inserted=1", cc)
	}
	// Nothing actually changed.
	got, _ := dst.clients.Get(ctx, "alpha")
	if got.Name != "Stale" {
		t.Errorf("dry-run mutated alpha: Name=%q", got.Name)
	}
}

// TestRestore_Exclude_SkipsCategory proves RestoreOptions.Exclude omits a
// whole category from the apply plan.
func TestRestore_Exclude_SkipsCategory(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{
		Mode:    snapshot.ModeMerge,
		Exclude: []snapshot.ResourceCategory{snapshot.CategoryUsers, snapshot.CategoryNetPolicy},
	})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	// Excluded categories must not appear in the report at all.
	if _, ok := rep.Items[snapshot.CategoryUsers]; ok {
		t.Errorf("excluded users category present in report")
	}
	if _, ok := rep.Items[snapshot.CategoryNetPolicy]; ok {
		t.Errorf("excluded netpolicy category present in report")
	}
	// And nothing landed for them.
	us, _ := dst.users.List(ctx)
	if len(us) != 0 {
		t.Errorf("excluded users still restored: %d", len(us))
	}
	ps, _ := dst.netpol.List(ctx)
	if len(ps) != 0 {
		t.Errorf("excluded netpolicy still restored: %d", len(ps))
	}
	// Clients (not excluded) still applied.
	if rep.Items[snapshot.CategoryClients].Inserted != 2 {
		t.Errorf("clients should still restore: %+v", rep.Items[snapshot.CategoryClients])
	}
}

// TestRestore_NilSnapshotRejected pins the nil-snapshot guard.
func TestRestore_NilSnapshotRejected(t *testing.T) {
	t.Parallel()
	dst := newBlank()
	if _, err := dst.restorer().Restore(context.Background(), nil, snapshot.RestoreOptions{}); err == nil {
		t.Fatal("want error for nil snapshot")
	}
}

// TestRestore_InvalidSnapshotRejected pins that Restore validates the
// snapshot envelope before applying anything.
func TestRestore_InvalidSnapshotRejected(t *testing.T) {
	t.Parallel()
	dst := newBlank()
	bad := &snapshot.Snapshot{SchemaVersion: "999", SourceNamespace: "ns", SnapshotID: "x"}
	if _, err := dst.restorer().Restore(context.Background(), bad, snapshot.RestoreOptions{}); err == nil {
		t.Fatal("want error for invalid schema version")
	}
}

// TestRestore_DefaultMode_IsMerge proves an empty Mode defaults to merge
// (the safest mode) rather than failing or wiping.
func TestRestore_DefaultMode_IsMerge(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(ctx, snapshot.ExportOptions{})

	dst := newBlank()
	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{}) // no Mode
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Mode != snapshot.ModeMerge {
		t.Errorf("default mode = %q, want %q", rep.Mode, snapshot.ModeMerge)
	}
	if rep.Items[snapshot.CategoryClients].Inserted != 2 {
		t.Errorf("default-merge did not insert clients: %+v", rep.Items[snapshot.CategoryClients])
	}
}

// snapshotter builds a Snapshotter wired to f's stores, mirroring
// fixture.snapshotter() — lets fixtureBlank double as an export source when
// a test needs full control over what's populated (e.g. a client with
// intentionally zero roles/assignments/menus, to exercise the exporter's
// "skip empty" convention deliberately).
func (f *fixtureBlank) snapshotter() *snapshot.Snapshotter {
	return &snapshot.Snapshotter{
		Clients:     f.clients,
		Users:       f.users,
		Permissions: f.perms,
		NetPolicy:   f.netpol,
		Tracker:     f.tracker,
		Namespace:   "sso-server",
	}
}

// TestRestore_Replace_WipesRolesForZeroEntryClient proves the ModeReplace
// prune fix: client "gamma" has ZERO roles at export time, so the exporter's
// size optimization gives it no ClientRoles entry — but it DOES appear in
// snap.Resources.Clients. A destination where gamma currently holds a role
// must have that role wiped by ModeReplace, not left untouched.
func TestRestore_Replace_WipesRolesForZeroEntryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := newBlank()
	if err := src.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.Resources.Roles) != 0 {
		t.Fatalf("fixture precondition failed: want zero role bundles, got %+v", snap.Resources.Roles)
	}

	dst := newBlank()
	if err := dst.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	if err := dst.perms.AddRole(ctx, "gamma", permissions.Role{Code: "stale-admin", Permissions: []string{"g:*"}}); err != nil {
		t.Fatalf("preseed role: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID})
	if err != nil {
		t.Fatalf("restore: %v\nreport=%+v", err, rep)
	}
	roles, err := dst.perms.ListAllRoles(ctx, "gamma")
	if err != nil {
		t.Fatalf("list roles: %v", err)
	}
	if len(roles) != 0 {
		t.Errorf("gamma roles not wiped by ModeReplace: %+v", roles)
	}
	if got := rep.Items[snapshot.CategoryRoles].Deleted; got != 1 {
		t.Errorf("roles deleted=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryRoles])
	}
}

// TestRestore_Replace_WipesAssignmentsForZeroEntryClient is the assignments
// analog of TestRestore_Replace_WipesRolesForZeroEntryClient: gamma has zero
// assignments at export time (no ClientAssignments entry), but a stale
// assignment in the destination must still be wiped by ModeReplace.
func TestRestore_Replace_WipesAssignmentsForZeroEntryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := newBlank()
	if err := src.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.Resources.Assignments) != 0 {
		t.Fatalf("fixture precondition failed: want zero assignment bundles, got %+v", snap.Resources.Assignments)
	}

	dst := newBlank()
	if err := dst.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	// MemoryProvider.AssignRoles doesn't validate the role code exists, so
	// no AddRole is needed to set up a stale assignment.
	if err := dst.perms.AssignRoles(ctx, "stale-user", "gamma", []string{"stale-admin"}); err != nil {
		t.Fatalf("preseed assignment: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID})
	if err != nil {
		t.Fatalf("restore: %v\nreport=%+v", err, rep)
	}
	assignments, err := dst.perms.ListAssignments(ctx, "gamma")
	if err != nil {
		t.Fatalf("list assignments: %v", err)
	}
	if len(assignments) != 0 {
		t.Errorf("gamma assignments not wiped by ModeReplace: %+v", assignments)
	}
	if got := rep.Items[snapshot.CategoryAssignments].Deleted; got != 1 {
		t.Errorf("assignments deleted=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryAssignments])
	}
}

// TestRestore_Replace_WipesMenusForZeroEntryClient is the menus analog: it
// also exercises the specific bug where restoreMenus short-circuited on
// len(snap.Resources.Menus) == 0 (true here, since gamma is the only client
// and has zero menus) before ever reaching the client roster, so ModeReplace
// never touched menus at all. A stale menu tree in the destination must
// still be wiped.
func TestRestore_Replace_WipesMenusForZeroEntryClient(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := newBlank()
	if err := src.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.Resources.Menus) != 0 {
		t.Fatalf("fixture precondition failed: want zero menu bundles, got %+v", snap.Resources.Menus)
	}

	dst := newBlank()
	if err := dst.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("preseed client: %v", err)
	}
	if err := dst.perms.SetMenus(ctx, "gamma", permissions.MenuTree{{ID: "stale-menu", Name: "Stale", Path: "/stale"}}); err != nil {
		t.Fatalf("preseed menu: %v", err)
	}

	rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID})
	if err != nil {
		t.Fatalf("restore: %v\nreport=%+v", err, rep)
	}
	menus, err := dst.perms.GetMenus(ctx, "gamma")
	if err != nil {
		t.Fatalf("get menus: %v", err)
	}
	if len(menus) != 0 {
		t.Errorf("gamma menus not wiped by ModeReplace: %+v", menus)
	}
	// SetMenus is a replace primitive, not a delete one — the wipe shows up
	// as Updated (existing tree present, replaced with empty), not Deleted.
	if got := rep.Items[snapshot.CategoryMenus].Updated; got != 1 {
		t.Errorf("menus updated=%d want 1 (%+v)", got, rep.Items[snapshot.CategoryMenus])
	}
}

// TestRestore_MergeOverwrite_LeavesZeroEntryClientPermissionsUntouched is the
// regression guard for the three ModeReplace fixes above: Merge and
// Overwrite must keep behaving exactly as before — touching only clients
// that actually have a roles/assignments/menus entry in the snapshot, never
// wiping based on snap.Resources.Clients membership alone.
func TestRestore_MergeOverwrite_LeavesZeroEntryClientPermissionsUntouched(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	src := newBlank()
	if err := src.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	snap, err := src.snapshotter().Export(ctx, snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	for _, mode := range []snapshot.RestoreMode{snapshot.ModeMerge, snapshot.ModeOverwrite} {
		t.Run(string(mode), func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			dst := newBlank()
			if err := dst.clients.Add(ctx, &sso.Client{ID: "gamma", Name: "Gamma"}); err != nil {
				t.Fatalf("preseed client: %v", err)
			}
			if err := dst.perms.AddRole(ctx, "gamma", permissions.Role{Code: "keep-admin", Permissions: []string{"g:*"}}); err != nil {
				t.Fatalf("preseed role: %v", err)
			}
			if err := dst.perms.AssignRoles(ctx, "keep-user", "gamma", []string{"keep-admin"}); err != nil {
				t.Fatalf("preseed assignment: %v", err)
			}
			if err := dst.perms.SetMenus(ctx, "gamma", permissions.MenuTree{{ID: "keep-menu", Name: "Keep", Path: "/keep"}}); err != nil {
				t.Fatalf("preseed menu: %v", err)
			}

			rep, err := dst.restorer().Restore(ctx, snap, snapshot.RestoreOptions{Mode: mode})
			if err != nil {
				t.Fatalf("restore: %v\nreport=%+v", err, rep)
			}

			roles, err := dst.perms.ListAllRoles(ctx, "gamma")
			if err != nil {
				t.Fatalf("list roles: %v", err)
			}
			if len(roles) != 1 || roles[0].Code != "keep-admin" {
				t.Errorf("%s wrongly touched gamma roles: %+v", mode, roles)
			}
			assignments, err := dst.perms.ListAssignments(ctx, "gamma")
			if err != nil {
				t.Fatalf("list assignments: %v", err)
			}
			if len(assignments) != 1 {
				t.Errorf("%s wrongly touched gamma assignments: %+v", mode, assignments)
			}
			menus, err := dst.perms.GetMenus(ctx, "gamma")
			if err != nil {
				t.Fatalf("get menus: %v", err)
			}
			if len(menus) != 1 {
				t.Errorf("%s wrongly touched gamma menus: %+v", mode, menus)
			}
			if got := rep.Items[snapshot.CategoryRoles].Deleted; got != 0 {
				t.Errorf("%s roles deleted=%d want 0", mode, got)
			}
			if got := rep.Items[snapshot.CategoryAssignments].Deleted; got != 0 {
				t.Errorf("%s assignments deleted=%d want 0", mode, got)
			}
		})
	}
}
