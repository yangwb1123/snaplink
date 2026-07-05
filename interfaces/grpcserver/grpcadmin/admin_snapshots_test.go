package grpcadmin

import (
	"context"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/snapshot"
	inline "github.com/snaplink/sso/interfaces/snapshot/storageinline"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
)

// TestSnapshotAdminService_NotConfiguredPreconditionFails proves every RPC
// returns FailedPrecondition rather than panicking when the mandatory
// pipeline+storage pair is unwired. This is deliberately the only case
// exercised for the "unconfigured" axis: standing up a full Snapshotter /
// Restorer pair (with real ClientStore/UserProvider backends) purely to
// prove Export/Restore ALSO fail when the OPTIONAL snapshotter/restorer is
// nil is covered below in TestSnapshotAdminService_OptionalDepsUnimplemented
// with a lighter fixture — heavier multi-backend wiring is exercised once in
// the FullCycle test instead of duplicated per precondition case.
func TestSnapshotAdminService_NotConfiguredPreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewSnapshotAdminService(nil, nil, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Export(ctx, &adminv1.ExportSnapshotRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.List(ctx, &adminv1.ListSnapshotsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Get(ctx, &adminv1.GetSnapshotRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Delete(ctx, &adminv1.DeleteSnapshotRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestSnapshotAdminService_OptionalDepsUnimplemented proves Export and
// Restore each independently need their OPTIONAL Snapshotter / Restorer,
// even once the mandatory Pipeline+Storage pair is present.
func TestSnapshotAdminService_OptionalDepsUnimplemented(t *testing.T) {
	t.Parallel()
	pipeline := &snapshot.Pipeline{}
	storage := inline.New()
	svc := NewSnapshotAdminService(pipeline, storage, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Export(ctx, &adminv1.ExportSnapshotRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
}

// snapshotFixture wires a source-side client store (what the Snapshotter
// exports) and a destination-side client store (what the Restorer applies
// into) sharing one in-memory Storage — mirroring the facade's bufconn
// fixture but without the gRPC transport layer.
type snapshotFixture struct {
	src *defaultimpl.MemoryClientStore
	dst *defaultimpl.MemoryClientStore
	svc *SnapshotAdminService
	rec *audit.Recorder
}

func newSnapshotFixture(sink *audit.MemorySink) *snapshotFixture {
	src := defaultimpl.NewMemoryClientStore()
	dst := defaultimpl.NewMemoryClientStore()
	storage := inline.New()
	pipeline := &snapshot.Pipeline{}
	snapper := &snapshot.Snapshotter{Clients: src, Namespace: "sso-server"}
	restorer := &snapshot.Restorer{Clients: dst, Namespace: "sso-server"}
	rec := audit.New(sink)
	return &snapshotFixture{
		src: src, dst: dst, rec: rec,
		svc: NewSnapshotAdminService(pipeline, storage, snapper, restorer, rec),
	}
}

// TestSnapshotAdminService_FullCycle drives Export -> List -> Get -> Restore
// -> Delete directly, proving a snapshot exported from one store's data can
// be restored into an entirely different store instance.
func TestSnapshotAdminService_FullCycle(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(50)
	fx := newSnapshotFixture(sink)
	ctx := context.Background()
	fx.src.AddSeed(&sso.Client{ID: "web-app", Name: "Web", Active: true})

	exp, err := fx.svc.Export(ctx, &adminv1.ExportSnapshotRequest{SourceNodeId: "node-A"})
	requireOK(t, err, "Export")
	if exp.Meta.SnapshotId == "" || exp.StoredAs != exp.Meta.SnapshotId {
		t.Errorf("Export response = %+v", exp)
	}

	list, err := fx.svc.List(ctx, &adminv1.ListSnapshotsRequest{})
	requireOK(t, err, "List")
	if len(list.Items) != 1 || list.Items[0].SnapshotId != exp.Meta.SnapshotId {
		t.Errorf("List = %+v", list.Items)
	}

	got, err := fx.svc.Get(ctx, &adminv1.GetSnapshotRequest{Id: exp.Meta.SnapshotId})
	requireOK(t, err, "Get")
	if len(got.ResourcesJson) == 0 {
		t.Error("Get returned empty ResourcesJson")
	}

	if _, err := fx.dst.Get(ctx, "web-app"); err == nil {
		t.Fatal("destination store must not already have web-app before Restore")
	}
	restore, err := fx.svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: exp.Meta.SnapshotId, Mode: string(snapshot.ModeMerge)})
	requireOK(t, err, "Restore")
	counts := restore.Report.Items["clients"]
	if counts == nil || counts.Inserted != 1 {
		t.Errorf("Restore report clients = %+v", counts)
	}
	if _, err := fx.dst.Get(ctx, "web-app"); err != nil {
		t.Errorf("expected Restore to have inserted web-app into the destination store: %v", err)
	}

	_, err = fx.svc.Delete(ctx, &adminv1.DeleteSnapshotRequest{Id: exp.Meta.SnapshotId})
	requireOK(t, err, "Delete")
	_, err = fx.svc.Get(ctx, &adminv1.GetSnapshotRequest{Id: exp.Meta.SnapshotId})
	requireCode(t, err, codes.NotFound)

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	if len(events) != 3 { // Export + Restore + Delete
		t.Errorf("expected 3 audit events, got %d", len(events))
	}
}

// TestSnapshotAdminService_RestoreValidation covers the Restore guard
// clauses: an unknown mode string is rejected before any Load happens, and
// ModeReplace requires a Confirm token equal to the snapshot ID.
func TestSnapshotAdminService_RestoreValidation(t *testing.T) {
	t.Parallel()
	fx := newSnapshotFixture(audit.NewMemorySink(20))
	ctx := context.Background()
	fx.src.AddSeed(&sso.Client{ID: "web-app", Active: true})
	exp, err := fx.svc.Export(ctx, &adminv1.ExportSnapshotRequest{})
	requireOK(t, err, "Export")

	_, err = fx.svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: exp.Meta.SnapshotId, Mode: "bogus"})
	requireCode(t, err, codes.InvalidArgument)

	_, err = fx.svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: exp.Meta.SnapshotId, Mode: string(snapshot.ModeReplace)})
	requireCode(t, err, codes.FailedPrecondition)

	_, err = fx.svc.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)

	_, err = fx.svc.Get(ctx, &adminv1.GetSnapshotRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = fx.svc.Delete(ctx, &adminv1.DeleteSnapshotRequest{})
	requireCode(t, err, codes.InvalidArgument)
}
