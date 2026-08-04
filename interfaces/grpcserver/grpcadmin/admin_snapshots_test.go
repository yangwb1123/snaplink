package grpcadmin

import (
	"bytes"
	"context"
	"sort"
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/snapshot"
	inline "github.com/yangwb1123/snaplink/interfaces/snapshot/storageinline"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/lifecycle/operations"
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
	ops *operations.MemoryStore
}

func newSnapshotFixture(sink *audit.MemorySink) *snapshotFixture {
	src := defaultimpl.NewMemoryClientStore()
	dst := defaultimpl.NewMemoryClientStore()
	storage := inline.New()
	pipeline := &snapshot.Pipeline{}
	snapper := &snapshot.Snapshotter{Clients: src, Namespace: "sso-server"}
	restorer := &snapshot.Restorer{Clients: dst, Namespace: "sso-server"}
	rec := audit.New(sink)
	ops := operations.NewMemoryStore()
	return &snapshotFixture{
		src: src, dst: dst, rec: rec, ops: ops,
		svc: NewSnapshotAdminService(pipeline, storage, snapper, restorer, rec, ops),
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
	fx.src.AddSeed(&sso.Client{
		ID: "web-app", Name: "Web", Active: true,
		Secret: "must-not-read", RegistrationAccessToken: "must-not-read-rat",
	})

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
	if bytes.Contains(got.ResourcesJson, []byte("must-not-read")) {
		t.Fatalf("Get exposed credential material: %s", got.ResourcesJson)
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
	tracked, err := fx.ops.Get(ctx, restore.OperationId)
	if err != nil || tracked.State != operations.StateSucceeded ||
		len(tracked.Steps) != 2 || restore.Operation.GetId() != restore.OperationId {
		t.Fatalf("restore operation = %+v, stored=%+v, err=%v", restore.Operation, tracked, err)
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
	// The replace-without-confirm failure is retained as a failed operation
	// (load step failed; the safety capture never ran — validation precedes
	// capture). The "missing" restore fails BEFORE operations.Start (the
	// D1 pre-Start kind peek is a read, and a not-found id must not write
	// anything, not even a ledger record) — so exactly one failed op exists.
	operationsList, listErr := fx.ops.List(ctx)
	requireOK(t, listErr, "list operations")
	if len(operationsList) != 1 || operationsList[0].State != operations.StateFailed {
		t.Fatalf("failed restores not retained: %+v", operationsList)
	}

	_, err = fx.svc.Get(ctx, &adminv1.GetSnapshotRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = fx.svc.Delete(ctx, &adminv1.DeleteSnapshotRequest{})
	requireCode(t, err, codes.InvalidArgument)
}

// TestSnapshotAdminService_ListPagination proves List bounds its response by
// page_size (fixed name-ascending sort, since Storage.List documents
// "arbitrary order" and this proto has no order_by field), that
// next_page_token round-trips to the remaining page, and that a garbage
// page_token is rejected. Regression coverage for a List RPC that used to
// ignore page_token/page_size entirely and return every snapshot unbounded.
func TestSnapshotAdminService_ListPagination(t *testing.T) {
	t.Parallel()
	fx := newSnapshotFixture(audit.NewMemorySink(50))
	ctx := context.Background()

	ids := make([]string, 0, 3)
	for _, cid := range []string{"client-a", "client-b", "client-c"} {
		fx.src.AddSeed(&sso.Client{ID: cid, Active: true})
		exp, err := fx.svc.Export(ctx, &adminv1.ExportSnapshotRequest{SourceNodeId: "node"})
		requireOK(t, err, "Export")
		ids = append(ids, exp.Meta.SnapshotId)
	}
	sort.Strings(ids) // List imposes name-ascending order, independent of export order

	page1, err := fx.svc.List(ctx, &adminv1.ListSnapshotsRequest{PageSize: 2})
	requireOK(t, err, "List page1")
	if len(page1.Items) != 2 || page1.TotalSize != 3 || page1.NextPageToken == "" {
		t.Fatalf("page1 = len=%d total=%d next=%q", len(page1.Items), page1.TotalSize, page1.NextPageToken)
	}
	if page1.Items[0].SnapshotId != ids[0] || page1.Items[1].SnapshotId != ids[1] {
		t.Errorf("page1 ids = [%s, %s], want [%s, %s]", page1.Items[0].SnapshotId, page1.Items[1].SnapshotId, ids[0], ids[1])
	}

	page2, err := fx.svc.List(ctx, &adminv1.ListSnapshotsRequest{PageSize: 2, PageToken: page1.NextPageToken})
	requireOK(t, err, "List page2")
	if len(page2.Items) != 1 || page2.Items[0].SnapshotId != ids[2] || page2.NextPageToken != "" {
		t.Errorf("page2 = %+v, want [%s] with no further token", page2.Items, ids[2])
	}

	_, err = fx.svc.List(ctx, &adminv1.ListSnapshotsRequest{PageToken: "!!!not-valid-base64!!!"})
	requireCode(t, err, codes.InvalidArgument)
}
