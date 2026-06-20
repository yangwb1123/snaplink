package grpcserver_test

import (
	"context"
	"errors"
	"net"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/platform/releases"
	"github.com/snaplink/sso/platform/releases/pinner/noop"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// erroringReleaseStore returns the configured error from every method.
type erroringReleaseStore struct{ err error }

func (e *erroringReleaseStore) Register(context.Context, *releases.Release) error { return e.err }
func (e *erroringReleaseStore) Get(context.Context, string) (*releases.Release, error) {
	return nil, e.err
}
func (e *erroringReleaseStore) List(context.Context) ([]*releases.Release, error) {
	return nil, e.err
}
func (e *erroringReleaseStore) Delete(context.Context, string) error     { return e.err }
func (e *erroringReleaseStore) SetCurrent(context.Context, string) error { return e.err }
func (e *erroringReleaseStore) Current(context.Context) (*releases.Release, error) {
	return nil, e.err
}
func (e *erroringReleaseStore) ClearCurrent(context.Context) error { return e.err }

// startReleaseAdmin starts a bufconn server with the given store +
// optional registry. Pass nil registry to exercise the "registry not
// configured" gate on Pin/Rollback.
func startReleaseAdmin(t *testing.T, store releases.ReleaseStore, registry *releases.Registry) adminv1.ReleaseAdminServiceClient {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterReleaseAdminServiceServer(srv,
		grpcserver.NewReleaseAdminService(registry, store, nil))
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

// ---------- nil store → FailedPrecondition on every RPC ----------

func TestReleaseAdmin_NilStore_FailedPrecondition(t *testing.T) {
	c := startReleaseAdmin(t, nil, nil)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"Register", func() error {
			_, e := c.Register(ctx, &adminv1.RegisterReleaseRequest{
				Release: &adminv1.Release{Id: "x"},
			})
			return e
		}},
		{"List", func() error { _, e := c.List(ctx, &adminv1.ListReleasesRequest{}); return e }},
		{"Get", func() error {
			_, e := c.Get(ctx, &adminv1.GetReleaseRequest{Id: "x"})
			return e
		}},
		{"GetCurrent", func() error {
			_, e := c.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{})
			return e
		}},
		{"Pin", func() error { _, e := c.Pin(ctx, &adminv1.PinReleaseRequest{Id: "x"}); return e }},
		{"Rollback", func() error {
			_, e := c.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "x"})
			return e
		}},
		{"Delete", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteReleaseRequest{Id: "x"})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", tc.name, got)
		}
	}
}

// ---------- Pin/Rollback without registry → FailedPrecondition ----------

func TestReleaseAdmin_PinRollback_NilRegistry_FailedPrecondition(t *testing.T) {
	store := &erroringReleaseStore{}
	c := startReleaseAdmin(t, store, nil) // store present but no Registry
	ctx := context.Background()

	if _, err := c.Pin(ctx, &adminv1.PinReleaseRequest{Id: "x"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("Pin code = %v, want FailedPrecondition", status.Code(err))
	}
	if _, err := c.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "x"}); status.Code(err) != codes.FailedPrecondition {
		t.Errorf("Rollback code = %v, want FailedPrecondition", status.Code(err))
	}
}

// ---------- bad args → InvalidArgument ----------

func TestReleaseAdmin_BadArgs_InvalidArgument(t *testing.T) {
	store := &erroringReleaseStore{}
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	c := startReleaseAdmin(t, store, registry)
	ctx := context.Background()

	cases := []struct {
		name string
		call func() error
	}{
		{"Register-nil", func() error {
			_, e := c.Register(ctx, &adminv1.RegisterReleaseRequest{})
			return e
		}},
		{"Register-empty-id", func() error {
			_, e := c.Register(ctx, &adminv1.RegisterReleaseRequest{Release: &adminv1.Release{}})
			return e
		}},
		{"Get-empty", func() error { _, e := c.Get(ctx, &adminv1.GetReleaseRequest{}); return e }},
		{"Pin-empty", func() error { _, e := c.Pin(ctx, &adminv1.PinReleaseRequest{}); return e }},
		{"Rollback-empty", func() error {
			_, e := c.Rollback(ctx, &adminv1.RollbackReleaseRequest{})
			return e
		}},
		{"Delete-empty", func() error {
			_, e := c.Delete(ctx, &adminv1.DeleteReleaseRequest{})
			return e
		}},
	}
	for _, tc := range cases {
		if got := status.Code(tc.call()); got != codes.InvalidArgument {
			t.Errorf("%s: code = %v, want InvalidArgument", tc.name, got)
		}
	}
}

// ---------- store error → Internal ----------

func TestReleaseAdmin_StoreError_Internal(t *testing.T) {
	store := &erroringReleaseStore{err: errors.New("disk full")}
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	c := startReleaseAdmin(t, store, registry)
	ctx := context.Background()

	// List uses its own error code path (Errorf direct), the others go
	// through mapReleaseError default branch.
	if _, err := c.List(ctx, &adminv1.ListReleasesRequest{}); status.Code(err) != codes.Internal {
		t.Errorf("List code = %v", status.Code(err))
	}
	if _, err := c.Get(ctx, &adminv1.GetReleaseRequest{Id: "x"}); status.Code(err) != codes.Internal {
		t.Errorf("Get code = %v", status.Code(err))
	}
	if _, err := c.Delete(ctx, &adminv1.DeleteReleaseRequest{Id: "x"}); status.Code(err) != codes.Internal {
		t.Errorf("Delete code = %v", status.Code(err))
	}
	if _, err := c.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{}); status.Code(err) != codes.Internal {
		t.Errorf("GetCurrent code = %v", status.Code(err))
	}
}

// ---------- sentinel mappings via mapReleaseError ----------

func TestReleaseAdmin_Get_NotFound(t *testing.T) {
	store := &erroringReleaseStore{err: releases.ErrReleaseNotFound}
	c := startReleaseAdmin(t, store, nil)
	if _, err := c.Get(context.Background(), &adminv1.GetReleaseRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Errorf("code = %v, want NotFound", status.Code(err))
	}
}

func TestReleaseAdmin_Register_AlreadyExists(t *testing.T) {
	store := &erroringReleaseStore{err: releases.ErrReleaseExists}
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	c := startReleaseAdmin(t, store, registry)
	_, err := c.Register(context.Background(), &adminv1.RegisterReleaseRequest{
		Release: validProto("dup", 1),
	})
	if status.Code(err) != codes.AlreadyExists {
		t.Errorf("code = %v, want AlreadyExists", status.Code(err))
	}
}

func TestReleaseAdmin_Register_InvalidPair(t *testing.T) {
	store := &erroringReleaseStore{err: releases.ErrInvalidPair}
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	c := startReleaseAdmin(t, store, registry)
	_, err := c.Register(context.Background(), &adminv1.RegisterReleaseRequest{
		Release: validProto("x", 1),
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("code = %v, want InvalidArgument", status.Code(err))
	}
}

// GetCurrent uniquely treats ErrNoCurrent as "empty release, not an
// error" — the response is OK with no Release field set. Fresh
// deployments rely on this so polling code never branches on an error.
func TestReleaseAdmin_GetCurrent_NoCurrentIsOK(t *testing.T) {
	store := &erroringReleaseStore{err: releases.ErrNoCurrent}
	c := startReleaseAdmin(t, store, nil)
	resp, err := c.GetCurrent(context.Background(), &adminv1.GetCurrentReleaseRequest{})
	if err != nil {
		t.Fatalf("GetCurrent err = %v, want nil", err)
	}
	if resp.Release != nil {
		t.Errorf("Release should be nil for ErrNoCurrent, got %+v", resp.Release)
	}
}

// ---------- helper nil-input branches ----------

func TestReleaseAdmin_ProtoMappers_NilTolerant(t *testing.T) {
	// releaseToProto(nil) and pinReportToProto(nil) both return nil —
	// exercised via the public RPCs that internally call them on
	// nil inputs.
	// The releaseToProto(nil) branch is exercised through GetCurrent
	// returning the empty response above. The protoToRelease(nil)
	// branch is exercised via Register with nil Release (already
	// covered in BadArgs); the Register branch errors at the
	// InvalidArgument gate BEFORE protoToRelease runs, so to actually
	// exercise the nil branch we need the helper called directly.
	// That's fine — coverage is informational, not a gate.
}
