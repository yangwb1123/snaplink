package grpcadmin

import (
	"context"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/pinnernoop"
	"github.com/snaplink/sso/platform/releases/storememory"
	"google.golang.org/grpc/codes"
)

func validReleaseProto(id string, schema int32) *adminv1.Release {
	return &adminv1.Release{
		Id:            id,
		Channel:       releases.ChannelStable,
		SchemaVersion: schema,
		Frontend:      &adminv1.Artifact{GitRef: "v" + id},
		Backend:       &adminv1.Artifact{GitRef: "v" + id},
	}
}

// TestReleaseAdminService_NilStorePreconditionFails proves every RPC returns
// FailedPrecondition when the store dependency is unwired.
func TestReleaseAdminService_NilStorePreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewReleaseAdminService(nil, nil, nil)
	ctx := context.Background()

	_, err := svc.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validReleaseProto("r1", 1)})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.List(ctx, &adminv1.ListReleasesRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Get(ctx, &adminv1.GetReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Delete(ctx, &adminv1.DeleteReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestReleaseAdminService_RegistryNilButStoreSetPinFails proves Pin/Rollback
// specifically need the Registry (not just the Store) — a service built
// with only a store (no registry) still answers Register/List/Get, but Pin
// and Rollback fail FailedPrecondition since they need the Pinner/Registry.
func TestReleaseAdminService_RegistryNilButStoreSetPinFails(t *testing.T) {
	t.Parallel()
	store := memory.New()
	svc := NewReleaseAdminService(nil, store, nil)
	ctx := context.Background()

	_, err := svc.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validReleaseProto("r1", 1)})
	requireOK(t, err, "Register")

	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "r1"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestReleaseAdminService_FullCycle drives Register/List/Get/Pin/Rollback/
// Delete directly against a real storememory.Store + noop.Pinner, mirroring
// the facade's bufconn-based TestReleaseAdmin_FullCycle but as plain Go
// method calls.
func TestReleaseAdminService_FullCycle(t *testing.T) {
	t.Parallel()
	store := memory.New()
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	svc := NewReleaseAdminService(registry, store, rec)
	ctx := context.Background()

	requireOK(t, register(ctx, svc, "rel-1", 1), "Register rel-1")
	requireOK(t, register(ctx, svc, "rel-2", 2), "Register rel-2")

	_, err := svc.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validReleaseProto("rel-1", 1)})
	requireCode(t, err, codes.AlreadyExists)

	list, err := svc.List(ctx, &adminv1.ListReleasesRequest{})
	requireOK(t, err, "List")
	if len(list.Items) != 2 {
		t.Errorf("List len=%d", len(list.Items))
	}

	pin1, err := svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "rel-1"})
	requireOK(t, err, "Pin rel-1")
	if pin1.Report.ReleaseId != "rel-1" || pin1.Report.PreviousId != "" {
		t.Errorf("Pin rel-1 report = %+v", pin1.Report)
	}

	cur, err := svc.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{})
	requireOK(t, err, "GetCurrent")
	if cur.Release.Id != "rel-1" {
		t.Errorf("GetCurrent = %+v", cur.Release)
	}

	// Forward pin to rel-2 (schema 2 >= schema 1) then roll back to rel-1.
	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "rel-2"})
	requireOK(t, err, "Pin rel-2")
	roll, err := svc.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "rel-1"})
	requireOK(t, err, "Rollback rel-1")
	if roll.Report.ReleaseId != "rel-1" || roll.Report.PreviousId != "rel-2" {
		t.Errorf("Rollback report = %+v", roll.Report)
	}

	got, err := svc.Get(ctx, &adminv1.GetReleaseRequest{Id: "rel-2"})
	requireOK(t, err, "Get rel-2")
	if got.Release.SchemaVersion != 2 {
		t.Errorf("Get rel-2 SchemaVersion = %d", got.Release.SchemaVersion)
	}
	_, err = svc.Get(ctx, &adminv1.GetReleaseRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)

	_, err = svc.Delete(ctx, &adminv1.DeleteReleaseRequest{Id: "rel-2"})
	requireOK(t, err, "Delete rel-2")
	_, err = svc.Get(ctx, &adminv1.GetReleaseRequest{Id: "rel-2"})
	requireCode(t, err, codes.NotFound)

	events, err := sink.Query(ctx, audit.Query{})
	requireOK(t, err, "sink.Query")
	if len(events) == 0 {
		t.Error("expected release mutations to record audit events")
	}
}

func register(ctx context.Context, svc *ReleaseAdminService, id string, schema int32) error {
	_, err := svc.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validReleaseProto(id, schema)})
	return err
}

// TestReleaseAdminService_InvalidArgumentAndSchemaRegress covers the
// validation guard clauses plus mapReleaseError's FailedPrecondition branch
// for a schema regression on Pin.
func TestReleaseAdminService_InvalidArgumentAndSchemaRegress(t *testing.T) {
	t.Parallel()
	store := memory.New()
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	svc := NewReleaseAdminService(registry, store, nil)
	ctx := context.Background()

	_, err := svc.Register(ctx, &adminv1.RegisterReleaseRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Get(ctx, &adminv1.GetReleaseRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Rollback(ctx, &adminv1.RollbackReleaseRequest{})
	requireCode(t, err, codes.InvalidArgument)
	_, err = svc.Delete(ctx, &adminv1.DeleteReleaseRequest{})
	requireCode(t, err, codes.InvalidArgument)

	requireOK(t, register(ctx, svc, "high", 5), "Register high")
	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "high"})
	requireOK(t, err, "Pin high")

	requireOK(t, register(ctx, svc, "low", 1), "Register low")
	_, err = svc.Pin(ctx, &adminv1.PinReleaseRequest{Id: "low"})
	requireCode(t, err, codes.FailedPrecondition)

	// The blocked pin must not have moved the current pointer.
	cur, err := svc.GetCurrent(context.Background(), &adminv1.GetCurrentReleaseRequest{})
	requireOK(t, err, "GetCurrent after schema-regress-blocked pin")
	if cur.Release.Id != "high" {
		t.Errorf("expected current to remain %q after a blocked regress pin, got %q", "high", cur.Release.Id)
	}
}

// TestReleaseAdminService_GetCurrentNoneNoOp proves the documented
// "nothing pinned" answer is an empty response, not an error, for a fresh
// store.
func TestReleaseAdminService_GetCurrentNoneNoOp(t *testing.T) {
	t.Parallel()
	store := memory.New()
	svc := NewReleaseAdminService(&releases.Registry{Store: store}, store, nil)
	resp, err := svc.GetCurrent(context.Background(), &adminv1.GetCurrentReleaseRequest{})
	requireOK(t, err, "GetCurrent on empty store")
	if resp.Release != nil {
		t.Errorf("expected nil Release on empty store, got %+v", resp.Release)
	}
}
