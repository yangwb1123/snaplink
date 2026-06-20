package snapshot_test

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/bootstrap/memory"
	"github.com/snaplink/sso/platform/netpolicy"
	netmemory "github.com/snaplink/sso/platform/netpolicy/memory"
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
	dst := newBlank()
	if _, err := dst.restorer().Restore(context.Background(), nil, snapshot.RestoreOptions{}); err == nil {
		t.Fatal("want error for nil snapshot")
	}
}

// TestRestore_InvalidSnapshotRejected pins that Restore validates the
// snapshot envelope before applying anything.
func TestRestore_InvalidSnapshotRejected(t *testing.T) {
	dst := newBlank()
	bad := &snapshot.Snapshot{SchemaVersion: "999", SourceNamespace: "ns", SnapshotID: "x"}
	if _, err := dst.restorer().Restore(context.Background(), bad, snapshot.RestoreOptions{}); err == nil {
		t.Fatal("want error for invalid schema version")
	}
}

// TestRestore_DefaultMode_IsMerge proves an empty Mode defaults to merge
// (the safest mode) rather than failing or wiping.
func TestRestore_DefaultMode_IsMerge(t *testing.T) {
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
