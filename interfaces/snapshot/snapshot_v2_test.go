package snapshot_test

import (
	"context"
	"errors"
	"testing"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/tenant"
	tenantmemory "github.com/yangwb1123/snaplink/domains/tenant/memory"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	"github.com/yangwb1123/snaplink/shared/security"
)

func TestSnapshotV2RoundTripsTenantRoutingState(t *testing.T) {
	ctx := context.Background()
	sourceTenants := tenantmemory.New()
	sourceConnections := connections.NewMemoryStore()
	mustSnapshotV2(t, sourceTenants.PutTenant(ctx, &tenant.Tenant{ID: "acme", Slug: "acme"}))
	mustSnapshotV2(t, sourceTenants.PutDomain(ctx, &tenant.Domain{Hostname: "acme.test", TenantID: "acme"}))
	mustSnapshotV2(t, sourceConnections.Upsert(ctx, &connections.Connection{
		ID: "acme-oidc", TenantID: "acme", Type: connections.TypeOIDC,
		Enabled: true, Domains: []string{"acme.test"},
	}))

	exporter := &snapshot.Snapshotter{
		Tenants: sourceTenants, Connections: sourceConnections, Namespace: "test",
	}
	exported, err := exporter.Export(ctx, snapshot.ExportOptions{})
	mustSnapshotV2(t, err)
	codec := snapshot.NewJSONCodec()
	encoded, err := codec.Marshal(exported)
	mustSnapshotV2(t, err)
	decoded, err := codec.Unmarshal(encoded)
	mustSnapshotV2(t, err)

	targetTenants := tenantmemory.New()
	targetConnections := connections.NewMemoryStore()
	restorer := &snapshot.Restorer{Tenants: targetTenants, Connections: targetConnections}
	report, err := restorer.Restore(ctx, decoded, snapshot.RestoreOptions{Mode: snapshot.ModeMerge})
	mustSnapshotV2(t, err)
	if report.Items[snapshot.CategoryTenants].Inserted != 1 ||
		report.Items[snapshot.CategoryTenantDomains].Inserted != 1 ||
		report.Items[snapshot.CategoryConnections].Inserted != 1 {
		t.Fatalf("unexpected v2 restore report: %+v", report.Items)
	}
	if _, err := targetTenants.GetDomain(ctx, "acme.test"); err != nil {
		t.Fatalf("restored tenant domain: %v", err)
	}
	if _, err := targetConnections.Get(ctx, "acme-oidc"); err != nil {
		t.Fatalf("restored connection: %v", err)
	}
}

func TestSnapshotV1ReplaceCannotDeleteV2Categories(t *testing.T) {
	ctx := context.Background()
	target := tenantmemory.New()
	mustSnapshotV2(t, target.PutTenant(ctx, &tenant.Tenant{ID: "existing", Slug: "existing"}))
	legacy := &snapshot.Snapshot{
		SchemaVersion: "1", SnapshotID: "legacy", SourceNamespace: "test",
	}
	report, err := (&snapshot.Restorer{Tenants: target}).Restore(ctx, legacy, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: legacy.SnapshotID,
	})
	mustSnapshotV2(t, err)
	if _, ok := report.Items[snapshot.CategoryTenants]; ok {
		t.Fatal("v1 snapshot attempted to reconcile a v2-only category")
	}
	if _, err := target.GetTenant(ctx, "existing"); err != nil {
		t.Fatalf("v1 replace deleted v2 tenant state: %v", err)
	}
}

func TestSnapshotV2RedactsConnectionSecretsWithoutMutatingStore(t *testing.T) {
	ctx := context.Background()
	store := connections.NewMemoryStore()
	mustSnapshotV2(t, store.Upsert(ctx, &connections.Connection{
		ID: "oidc", TenantID: "acme", Type: connections.TypeOIDC,
		Config: map[string]string{
			"client_secret":  "live-secret",
			"token_endpoint": "https://idp.test/token",
		},
	}))
	exporter := &snapshot.Snapshotter{
		Connections: store, Namespace: "test",
		DefaultExportRedactor: snapshot.SnapshotRedactSecrets(),
	}
	exported, err := exporter.Export(ctx, snapshot.ExportOptions{})
	mustSnapshotV2(t, err)
	if _, ok := exported.Resources.Connections[0].Config["client_secret"]; ok {
		t.Fatal("connection secret survived snapshot redaction")
	}
	if exported.Resources.Connections[0].Config["token_endpoint"] == "" {
		t.Fatal("redaction removed non-secret token endpoint")
	}
	live, err := store.Get(ctx, "oidc")
	mustSnapshotV2(t, err)
	if live.Config["client_secret"] != "live-secret" {
		t.Fatal("snapshot redaction mutated the live connection store")
	}
}

func TestSnapshotV2ReplaceRoundTripsPairwiseSubjects(t *testing.T) {
	ctx := context.Background()
	source := security.NewMemoryPairwiseSubjectStore()
	mustSnapshotV2(t, source.MapPairwise(ctx, "pairwise-a", "alice"))
	exported, err := (&snapshot.Snapshotter{
		Pairwise: source, Namespace: "test",
	}).Export(ctx, snapshot.ExportOptions{})
	mustSnapshotV2(t, err)
	if !exported.IncludesCategory(snapshot.CategoryPairwise) {
		t.Fatal("pairwise category missing from v2 export")
	}

	target := security.NewMemoryPairwiseSubjectStore()
	invalidator := &countingRestoreInvalidator{}
	mustSnapshotV2(t, target.MapPairwise(ctx, "pairwise-a", "wrong"))
	mustSnapshotV2(t, target.MapPairwise(ctx, "stale", "bob"))
	report, err := (&snapshot.Restorer{Pairwise: target, Invalidator: invalidator}).Restore(ctx, exported, snapshot.RestoreOptions{
		Mode: snapshot.ModeReplace, Confirm: exported.SnapshotID,
	})
	mustSnapshotV2(t, err)
	counts := report.Items[snapshot.CategoryPairwise]
	if counts.Updated != 1 || counts.Deleted != 1 {
		t.Fatalf("unexpected pairwise restore counts: %+v", counts)
	}
	local, err := target.LocalSubject(ctx, "pairwise-a")
	mustSnapshotV2(t, err)
	if local != "alice" {
		t.Fatalf("restored local subject = %q, want alice", local)
	}
	if _, err := target.LocalSubject(ctx, "stale"); !errors.Is(err, security.ErrPairwiseUnknown) {
		t.Fatalf("stale mapping survived replace: %v", err)
	}
	if invalidator.calls != 1 {
		t.Fatalf("restore invalidations = %d, want 1", invalidator.calls)
	}
}

type countingRestoreInvalidator struct{ calls int }

func (i *countingRestoreInvalidator) InvalidateRestoredControlPlane() { i.calls++ }

func mustSnapshotV2(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
