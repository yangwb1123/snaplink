package snapshot_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/bootstrap"
	"github.com/yangwb1123/snaplink/platform/bootstrap/memory"
	"github.com/yangwb1123/snaplink/platform/netpolicy"
	netmemory "github.com/yangwb1123/snaplink/platform/netpolicy/memory"
	"github.com/yangwb1123/snaplink/shared/security"
)

// fixture builds a populated source environment: 2 clients, 2 users,
// a couple of roles + assignments, a menu tree, and a netpolicy.
type fixture struct {
	clients *defaultimpl.MemoryClientStore
	users   *defaultimpl.MemoryUserProvider
	perms   *permissions.MemoryProvider
	netpol  *netmemory.Store
	tracker *memory.Tracker
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	ctx := context.Background()
	f := &fixture{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}

	mustErr := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("fixture: %v", err)
		}
	}

	// clients
	mustErr(f.clients.Add(ctx, &sso.Client{ID: "alpha", Name: "Alpha", Active: true, RedirectURIs: []string{"https://a.example/cb"}}))
	mustErr(f.clients.Add(ctx, &sso.Client{ID: "beta", Name: "Beta", Active: true, RedirectURIs: []string{"https://b.example/cb"}}))
	// users
	mustErr(f.users.CreateOrUpdate(ctx, &sso.User{ID: "u1", Email: "u1@example", CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}))
	mustErr(f.users.CreateOrUpdate(ctx, &sso.User{ID: "u2", Email: "u2@example", CreatedAt: time.Unix(0, 0).UTC(), UpdatedAt: time.Unix(0, 0).UTC()}))
	// roles
	mustErr(f.perms.AddRole(ctx, "alpha", permissions.Role{Code: "admin", Permissions: []string{"a:*"}}))
	mustErr(f.perms.AddRole(ctx, "alpha", permissions.Role{Code: "viewer", Permissions: []string{"a:read"}}))
	mustErr(f.perms.AddRole(ctx, "beta", permissions.Role{Code: "writer", Permissions: []string{"b:write"}}))
	// menus
	mustErr(f.perms.SetMenus(ctx, "alpha", permissions.MenuTree{
		{ID: "m1", Name: "Dashboards", Path: "/d", Permission: "a:read"},
	}))
	// assignments
	mustErr(f.perms.AssignRoles(ctx, "u1", "alpha", []string{"admin"}))
	mustErr(f.perms.AssignRoles(ctx, "u2", "beta", []string{"writer"}))
	// netpolicy
	if _, err := f.netpol.Apply(ctx, &netpolicy.Policy{Name: "internal", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("netpol: %v", err)
	}
	// bootstrap state — pretend we ran versions 1 + 2.
	mustErr(f.tracker.MarkApplied(ctx, "sso-server", 2, "fixture"))
	return f
}

func (f *fixture) snapshotter() *snapshot.Snapshotter {
	return &snapshot.Snapshotter{
		Clients:     f.clients,
		Users:       f.users,
		Permissions: f.perms,
		NetPolicy:   f.netpol,
		Tracker:     f.tracker,
		Namespace:   "sso-server",
	}
}

func TestExport_Full(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	snap, err := f.snapshotter().Export(context.Background(), snapshot.ExportOptions{SourceNodeID: "node-A"})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if snap.SchemaVersion != snapshot.SchemaVersion {
		t.Errorf("schema_version=%q want %q", snap.SchemaVersion, snapshot.SchemaVersion)
	}
	if !strings.HasPrefix(snap.SnapshotID, "snap_") {
		t.Errorf("snapshot id missing prefix: %q", snap.SnapshotID)
	}
	if snap.SourceNodeID != "node-A" {
		t.Errorf("source_node_id=%q", snap.SourceNodeID)
	}
	if snap.BootstrapState.AppliedVersion != 2 {
		t.Errorf("bootstrap version=%d want 2", snap.BootstrapState.AppliedVersion)
	}
	if got := len(snap.Resources.Clients); got != 2 {
		t.Errorf("clients=%d want 2", got)
	}
	if got := len(snap.Resources.Users); got != 2 {
		t.Errorf("users=%d want 2", got)
	}
	// roles per client — 2 entries (alpha + beta), each with non-empty roles.
	if got := len(snap.Resources.Roles); got != 2 {
		t.Errorf("role-bundles=%d want 2", got)
	}
	if got := len(snap.Resources.Menus); got != 1 {
		t.Errorf("menu-bundles=%d want 1", got)
	}
	if got := len(snap.Resources.Assignments); got != 2 {
		t.Errorf("assignment-bundles=%d want 2", got)
	}
	if got := len(snap.Resources.NetPolicy); got != 1 {
		t.Errorf("netpolicy=%d want 1", got)
	}
}

func TestExport_Exclude(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	snap, err := f.snapshotter().Export(context.Background(), snapshot.ExportOptions{
		Exclude: []snapshot.ResourceCategory{snapshot.CategoryNetPolicy, snapshot.CategoryUsers},
	})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if got := len(snap.Resources.Users); got != 0 {
		t.Errorf("users not excluded, got %d", got)
	}
	if got := len(snap.Resources.NetPolicy); got != 0 {
		t.Errorf("netpolicy not excluded, got %d", got)
	}
	if got := len(snap.Resources.Clients); got != 2 {
		t.Errorf("clients should still be there, got %d", got)
	}
}

func TestExport_NoBackends(t *testing.T) {
	t.Parallel()
	s := &snapshot.Snapshotter{Namespace: "sso-server"}
	snap, err := s.Export(context.Background(), snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if len(snap.Resources.Clients)+len(snap.Resources.Users)+len(snap.Resources.NetPolicy) != 0 {
		t.Errorf("expected empty snapshot, got something")
	}
}

func TestRestore_Merge_FreshDestination(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, err := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})
	if err != nil {
		t.Fatalf("export: %v", err)
	}

	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
	r := dst.restorer()
	rep, err := r.Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("restore: %v\nreport=%+v", err, rep)
	}
	if rep.Items[snapshot.CategoryClients].Inserted != 2 {
		t.Errorf("clients inserted=%d want 2", rep.Items[snapshot.CategoryClients].Inserted)
	}
	if rep.Items[snapshot.CategoryUsers].Inserted != 2 {
		t.Errorf("users inserted=%d want 2", rep.Items[snapshot.CategoryUsers].Inserted)
	}
	if rep.Items[snapshot.CategoryNetPolicy].Inserted != 1 {
		t.Errorf("netpolicy inserted=%d want 1", rep.Items[snapshot.CategoryNetPolicy].Inserted)
	}
	if !rep.Bootstrap.Attempted || rep.Bootstrap.To != 2 {
		t.Errorf("bootstrap advance unexpected: %+v", rep.Bootstrap)
	}
	v, _ := dst.tracker.AppliedVersion(context.Background(), "sso-server")
	if v != 2 {
		t.Errorf("dst tracker version=%d want 2", v)
	}
}

func TestRestore_Merge_SkipsExisting(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	// pre-seed dst with one client so we exercise the skip branch.
	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
	_ = dst.clients.Add(context.Background(), &sso.Client{ID: "alpha", Name: "Pre-existing"})

	rep, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Items[snapshot.CategoryClients].Skipped != 1 {
		t.Errorf("expected 1 skipped, got %+v", rep.Items[snapshot.CategoryClients])
	}
	if rep.Items[snapshot.CategoryClients].Inserted != 1 {
		t.Errorf("expected 1 inserted, got %+v", rep.Items[snapshot.CategoryClients])
	}
	got, _ := dst.clients.Get(context.Background(), "alpha")
	if got.Name != "Pre-existing" {
		t.Errorf("merge should leave alpha untouched, got Name=%q", got.Name)
	}
}

func TestRestore_Overwrite_Updates(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
	_ = dst.clients.Add(context.Background(), &sso.Client{ID: "alpha", Name: "Stale"})

	rep, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeOverwrite})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Items[snapshot.CategoryClients].Updated != 1 {
		t.Errorf("expected 1 updated, got %+v", rep.Items[snapshot.CategoryClients])
	}
	got, _ := dst.clients.Get(context.Background(), "alpha")
	if got.Name != "Alpha" {
		t.Errorf("overwrite should update name, got %q", got.Name)
	}
}

func TestRestore_Replace_RequiresConfirm(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}

	// no confirm token → ErrConfirmationRequired
	if _, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace}); !errors.Is(err, snapshot.ErrConfirmationRequired) {
		t.Errorf("want ErrConfirmationRequired, got %v", err)
	}
	// wrong confirm token → ErrConfirmationMismatch
	if _, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: "nope"}); !errors.Is(err, snapshot.ErrConfirmationMismatch) {
		t.Errorf("want ErrConfirmationMismatch, got %v", err)
	}
}

func TestRestore_Replace_DeletesOrphans(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
	// pre-seed with extra client + user that aren't in the snapshot.
	_ = dst.clients.Add(context.Background(), &sso.Client{ID: "orphan", Name: "Orphan"})
	_ = dst.users.CreateOrUpdate(context.Background(), &sso.User{ID: "orphan-user"})

	rep, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeReplace, Confirm: snap.SnapshotID})
	if err != nil {
		t.Fatalf("restore: %v", err)
	}
	if rep.Items[snapshot.CategoryClients].Deleted != 1 {
		t.Errorf("clients deleted=%d want 1", rep.Items[snapshot.CategoryClients].Deleted)
	}
	if rep.Items[snapshot.CategoryUsers].Deleted != 1 {
		t.Errorf("users deleted=%d want 1", rep.Items[snapshot.CategoryUsers].Deleted)
	}
	// confirm orphan is gone
	if _, err := dst.clients.Get(context.Background(), "orphan"); err == nil {
		t.Errorf("orphan client should be deleted")
	}
}

func TestRestore_DryRun_NoMutation(t *testing.T) {
	t.Parallel()
	src := newFixture(t)
	snap, _ := src.snapshotter().Export(context.Background(), snapshot.ExportOptions{})

	dst := &fixtureBlank{
		clients: defaultimpl.NewMemoryClientStore(),
		users:   defaultimpl.NewMemoryUserProvider(),
		perms:   permissions.NewMemoryProvider(),
		netpol:  netmemory.New(),
		tracker: memory.New(),
	}
	rep, err := dst.restorer().Restore(context.Background(), snap, snapshot.RestoreOptions{Mode: snapshot.ModeMerge, DryRun: true, AdvanceBootstrap: true})
	if err != nil {
		t.Fatalf("dry-run: %v", err)
	}
	if !rep.DryRun {
		t.Errorf("DryRun flag not propagated to report")
	}
	if rep.Items[snapshot.CategoryClients].Inserted != 2 {
		t.Errorf("dry-run should still report inserted counts: %+v", rep.Items[snapshot.CategoryClients])
	}
	// destination must be untouched
	cs, _ := dst.clients.List(context.Background())
	if len(cs) != 0 {
		t.Errorf("destination clients=%d after dry-run, want 0", len(cs))
	}
	v, _ := dst.tracker.AppliedVersion(context.Background(), "sso-server")
	if v != 0 {
		t.Errorf("tracker advanced during dry-run: %d", v)
	}
}

// fixtureBlank holds the destination side of restore tests — separate
// type so it doesn't accidentally inherit fixture's pre-seeding. Fields are
// interface-typed so tests can inject failing wrappers (failFirst*) and
// capability-limited backends (barePairwiseStore) at exactly one seam.
type fixtureBlank struct {
	clients  sso.ClientStore
	users    sso.UserProvider
	perms    permissions.Provider
	netpol   netpolicy.Store
	tracker  bootstrap.Tracker
	pairwise security.PairwiseSubjectStore
}

func (f *fixtureBlank) restorer() *snapshot.Restorer {
	return &snapshot.Restorer{
		Clients:     f.clients,
		Users:       f.users,
		Permissions: f.perms,
		NetPolicy:   f.netpol,
		Pairwise:    f.pairwise,
		Tracker:     f.tracker,
		Namespace:   "sso-server",
	}
}

func (f *fixtureBlank) snapshotter() *snapshot.Snapshotter {
	return &snapshot.Snapshotter{
		Clients:     f.clients,
		Users:       f.users,
		Permissions: f.perms,
		NetPolicy:   f.netpol,
		Pairwise:    f.pairwise,
		Namespace:   "sso-server",
	}
}
