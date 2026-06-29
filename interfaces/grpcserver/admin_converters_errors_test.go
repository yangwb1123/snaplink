package grpcserver_test

// Coverage for the remaining admin-service branches: the snapshot/release
// readiness gates and sentinel->status-code mappers, plus the nil proto
// converters reached through nil-returning stores. These pin defensive paths
// the happy-path fixtures don't exercise.

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/snaplink/sso/domains/tenant"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/pinnernoop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// --- snapshot readiness + mapper coverage ---

// erroringStorage returns the configured error from Get/List/Delete so the
// snapshot mapper branches (NotFound, DataLoss, FailedPrecondition, Internal)
// can be driven through the public RPC surface.
type erroringStorage struct{ err error }

func (e *erroringStorage) Put(context.Context, string, []byte) error { return e.err }
func (e *erroringStorage) Get(context.Context, string) ([]byte, error) {
	return nil, e.err
}
func (e *erroringStorage) List(context.Context) ([]string, error) { return nil, e.err }
func (e *erroringStorage) Delete(context.Context, string) error   { return e.err }

var _ snapshot.Storage = (*erroringStorage)(nil)

func startSnapshotAdmin(t *testing.T, p *snapshot.Pipeline, st snapshot.Storage, sn *snapshot.Snapshotter, r *snapshot.Restorer) adminv1.SnapshotAdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterSnapshotAdminServiceServer(srv, grpcserver.NewSnapshotAdminService(p, st, sn, r, nil))
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return adminv1.NewSnapshotAdminServiceClient(conn)
}

func TestSnapshotAdmin_NotReadyFailsPrecondition(t *testing.T) {
	t.Parallel()
	// Nil pipeline/storage -> ready() gate fires on every RPC.
	c := startSnapshotAdmin(t, nil, nil, nil, nil)
	ctx := context.Background()
	cases := map[string]func() error{
		"Export":  func() error { _, e := c.Export(ctx, &adminv1.ExportSnapshotRequest{}); return e },
		"List":    func() error { _, e := c.List(ctx, &adminv1.ListSnapshotsRequest{}); return e },
		"Get":     func() error { _, e := c.Get(ctx, &adminv1.GetSnapshotRequest{Id: "s"}); return e },
		"Restore": func() error { _, e := c.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: "s"}); return e },
		"Delete":  func() error { _, e := c.Delete(ctx, &adminv1.DeleteSnapshotRequest{Id: "s"}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, got)
		}
	}
}

func TestSnapshotAdmin_ExportWithoutSnapshotterFailsPrecondition(t *testing.T) {
	t.Parallel()
	// Pipeline + storage present but no Snapshotter -> Export-specific gate.
	c := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{}, nil, nil)
	if _, err := c.Export(context.Background(), &adminv1.ExportSnapshotRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestSnapshotAdmin_RestoreWithoutRestorerFailsPrecondition(t *testing.T) {
	t.Parallel()
	c := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{}, nil, nil)
	if _, err := c.Restore(context.Background(), &adminv1.RestoreSnapshotRequest{Id: "s"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestSnapshotAdmin_EmptyIDIsInvalidArgument(t *testing.T) {
	t.Parallel()
	c := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{}, nil, &snapshot.Restorer{})
	ctx := context.Background()
	cases := map[string]func() error{
		"Get":     func() error { _, e := c.Get(ctx, &adminv1.GetSnapshotRequest{}); return e },
		"Restore": func() error { _, e := c.Restore(ctx, &adminv1.RestoreSnapshotRequest{}); return e },
		"Delete":  func() error { _, e := c.Delete(ctx, &adminv1.DeleteSnapshotRequest{}); return e },
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", name, got)
		}
	}
}

func TestSnapshotAdmin_MapperCodes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// NotFound: storage returns ErrSnapshotNotFound.
	cNF := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{err: snapshot.ErrSnapshotNotFound}, nil, nil)
	if _, err := cNF.Get(ctx, &adminv1.GetSnapshotRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("ErrSnapshotNotFound -> got %v, want NotFound", status.Code(err))
	}
	if _, err := cNF.Delete(ctx, &adminv1.DeleteSnapshotRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("Delete ErrSnapshotNotFound -> got %v, want NotFound", status.Code(err))
	}
	// DataLoss: checksum mismatch.
	cDL := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{err: snapshot.ErrChecksumMismatch}, nil, nil)
	if _, err := cDL.Get(ctx, &adminv1.GetSnapshotRequest{Id: "x"}); status.Code(err) != codes.DataLoss {
		t.Errorf("ErrChecksumMismatch -> got %v, want DataLoss", status.Code(err))
	}
	// FailedPrecondition: unknown schema version (mapped via mapSnapshotError).
	cFP := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{err: snapshot.ErrUnknownSchemaVersion}, nil, nil)
	if _, err := cFP.Get(ctx, &adminv1.GetSnapshotRequest{Id: "x"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("ErrUnknownSchemaVersion -> got %v, want FailedPrecondition", status.Code(err))
	}
	// Internal: generic error.
	cI := startSnapshotAdmin(t, &snapshot.Pipeline{}, &erroringStorage{err: errors.New("disk gone")}, nil, nil)
	if _, err := cI.Get(ctx, &adminv1.GetSnapshotRequest{Id: "x"}); status.Code(err) != codes.Internal {
		t.Errorf("generic err -> got %v, want Internal", status.Code(err))
	}
}

func TestSnapshotAdmin_ListGetErrorIsMapped(t *testing.T) {
	t.Parallel()
	// List calls storage.List successfully but the per-item Get fails: drive
	// the mapSnapshotError branch inside the List loop. erroringStorage.List
	// returns its err, so use a storage that lists one name then fails Get.
	c := startSnapshotAdmin(t, &snapshot.Pipeline{}, &listThenFailStorage{name: "snap-1"}, nil, nil)
	if _, err := c.List(context.Background(), &adminv1.ListSnapshotsRequest{}); status.Code(err) != codes.NotFound {
		t.Fatalf("List per-item Get error -> got %v, want NotFound", status.Code(err))
	}
}

// listThenFailStorage returns one name from List but ErrSnapshotNotFound from
// Get, exercising the List-loop error branch.
type listThenFailStorage struct {
	erroringStorage
	name string
}

func (l *listThenFailStorage) List(context.Context) ([]string, error) { return []string{l.name}, nil }
func (l *listThenFailStorage) Get(context.Context, string) ([]byte, error) {
	return nil, snapshot.ErrSnapshotNotFound
}

// --- release readiness + nil registry ---

func startReleaseAdminClient(t *testing.T, reg *releases.Registry, store releases.ReleaseStore) adminv1.ReleaseAdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterReleaseAdminServiceServer(srv, grpcserver.NewReleaseAdminService(reg, store, nil))
	go func() { _ = srv.Serve(lis) }()
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return adminv1.NewReleaseAdminServiceClient(conn)
}

func TestReleaseAdmin_GetCurrentNilStoreFailsPrecondition(t *testing.T) {
	t.Parallel()
	c := startReleaseAdminClient(t, nil, nil)
	if _, err := c.GetCurrent(context.Background(), &adminv1.GetCurrentReleaseRequest{}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestReleaseAdmin_GetCurrentInternalError(t *testing.T) {
	t.Parallel()
	// A non-ErrNoCurrent error from Current() maps to Internal via
	// mapReleaseError (the GetCurrent default branch).
	store := &erroringReleaseStore{err: errors.New("db down")}
	reg := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	c := startReleaseAdminClient(t, reg, store)
	if _, err := c.GetCurrent(context.Background(), &adminv1.GetCurrentReleaseRequest{}); status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}

// --- nil proto converters via nil-returning stores ---

func TestTenantAdmin_GetTenantNilProto(t *testing.T) {
	t.Parallel()
	// A store that returns (nil, nil) drives the nil branch of tenantToProto.
	store := &nilTenantStore{}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	resp, err := c.GetTenant(context.Background(), &adminv1.GetTenantRequest{Id: "x"})
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if resp.Tenant != nil {
		t.Errorf("expected nil proto tenant, got %+v", resp.Tenant)
	}
}

func TestTenantAdmin_GetDomainNilProto(t *testing.T) {
	t.Parallel()
	store := &nilTenantStore{}
	conn := startTenantAdminGRPC(t, store, nil, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	resp, err := c.GetDomain(context.Background(), &adminv1.GetDomainRequest{Hostname: "h"})
	if err != nil {
		t.Fatalf("GetDomain: %v", err)
	}
	if resp.Domain != nil {
		t.Errorf("expected nil proto domain, got %+v", resp.Domain)
	}
}

// nilTenantStore returns (nil, nil) from GetTenant/GetDomain to drive the
// nil branches of tenantToProto / domainToProto. Embeds the shared
// erroringTenantStore for the remaining tenant.Store methods.
type nilTenantStore struct{ erroringTenantStore }

func (n *nilTenantStore) GetTenant(context.Context, string) (*tenant.Tenant, error) {
	return nil, nil
}
func (n *nilTenantStore) GetDomain(context.Context, string) (*tenant.Domain, error) {
	return nil, nil
}
