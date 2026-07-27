package grpcserver_test

import (
	"context"
	"net"
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/releases"
	"github.com/yangwb1123/snaplink/platform/releases/pinnernoop"
	"github.com/yangwb1123/snaplink/platform/releases/storememory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type releaseFixture struct {
	store *memory.Store
	sink  *audit.MemorySink
	conn  *grpc.ClientConn
}

func startReleaseGRPC(t *testing.T) *releaseFixture {
	t.Helper()
	store := memory.New()
	registry := &releases.Registry{Store: store, Pinner: noop.Pinner{}}
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterReleaseAdminServiceServer(srv,
		grpcserver.NewReleaseAdminService(registry, store, rec))
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
	return &releaseFixture{store: store, sink: sink, conn: conn}
}

func validProto(id string, schema int32) *adminv1.Release {
	return &adminv1.Release{
		Id:            id,
		Channel:       releases.ChannelStable,
		SchemaVersion: schema,
		Frontend:      &adminv1.Artifact{GitRef: "v" + id},
		Backend:       &adminv1.Artifact{GitRef: "v" + id},
	}
}

func TestReleaseAdmin_FullCycle(t *testing.T) {
	t.Parallel()
	fx := startReleaseGRPC(t)
	c := adminv1.NewReleaseAdminServiceClient(fx.conn)
	ctx := context.Background()

	// Register two releases.
	if _, err := c.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validProto("rel-1", 1)}); err != nil {
		t.Fatalf("Register rel-1: %v", err)
	}
	if _, err := c.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validProto("rel-2", 2)}); err != nil {
		t.Fatalf("Register rel-2: %v", err)
	}
	// Duplicate → AlreadyExists.
	if _, err := c.Register(ctx, &adminv1.RegisterReleaseRequest{Release: validProto("rel-1", 1)}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}

	// List sorted.
	list, err := c.List(ctx, &adminv1.ListReleasesRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 2 {
		t.Errorf("List len=%d", len(list.Items))
	}

	// Current before any pin → empty release, no error.
	cur, err := c.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{})
	if err != nil {
		t.Fatalf("GetCurrent fresh: %v", err)
	}
	if cur.Release != nil {
		t.Errorf("fresh GetCurrent returned %+v", cur.Release)
	}

	// Pin rel-1.
	pin1, err := c.Pin(ctx, &adminv1.PinReleaseRequest{Id: "rel-1"})
	if err != nil {
		t.Fatalf("Pin rel-1: %v", err)
	}
	if pin1.Report.Mode != "forward" || pin1.Report.PreviousId != "" {
		t.Errorf("pin1 report: %+v", pin1.Report)
	}

	// Pin rel-2 — forward + previous=rel-1.
	pin2, err := c.Pin(ctx, &adminv1.PinReleaseRequest{Id: "rel-2"})
	if err != nil {
		t.Fatalf("Pin rel-2: %v", err)
	}
	if pin2.Report.PreviousId != "rel-1" {
		t.Errorf("pin2 previous=%q", pin2.Report.PreviousId)
	}

	// Forward Pin back to rel-1 (schema regression) → FailedPrecondition.
	if _, err := c.Pin(ctx, &adminv1.PinReleaseRequest{Id: "rel-1"}); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("schema-regression Pin: expected FailedPrecondition, got %v", err)
	}

	// Rollback to rel-1 should work despite schema regression.
	rb, err := c.Rollback(ctx, &adminv1.RollbackReleaseRequest{Id: "rel-1"})
	if err != nil {
		t.Fatalf("Rollback: %v", err)
	}
	if rb.Report.Mode != "rollback" || rb.Report.ReleaseId != "rel-1" {
		t.Errorf("rollback report: %+v", rb.Report)
	}

	// Current = rel-1.
	cur2, _ := c.GetCurrent(ctx, &adminv1.GetCurrentReleaseRequest{})
	if cur2.Release == nil || cur2.Release.Id != "rel-1" {
		t.Errorf("Current after rollback = %+v", cur2.Release)
	}

	// Delete rel-2.
	if _, err := c.Delete(ctx, &adminv1.DeleteReleaseRequest{Id: "rel-2"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, &adminv1.GetReleaseRequest{Id: "rel-2"}); status.Code(err) != codes.NotFound {
		t.Fatalf("after Delete: expected NotFound, got %v", err)
	}

	// Audit: Register x2 + Pin x2 + Rollback x1 + Delete x1 = 6 events.
	if got := fx.sink.Len(); got != 6 {
		t.Errorf("audit events = %d, want 6", got)
	}
	want := map[audit.EventType]int{
		audit.EventReleaseRegistered: 2,
		audit.EventReleasePinned:     2,
		audit.EventReleaseRolledBack: 1,
		audit.EventReleaseDeleted:    1,
	}
	got := map[audit.EventType]int{}
	events, err := fx.sink.Query(ctx, audit.Query{Limit: 50})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, e := range events {
		got[e.Type]++
	}
	for typ, n := range want {
		if got[typ] != n {
			t.Errorf("event %q count = %d, want %d", typ, got[typ], n)
		}
	}
}

func TestReleaseAdmin_GetUnknownIs404(t *testing.T) {
	t.Parallel()
	fx := startReleaseGRPC(t)
	c := adminv1.NewReleaseAdminServiceClient(fx.conn)
	if _, err := c.Get(context.Background(), &adminv1.GetReleaseRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestReleaseAdmin_RegisterInvalidPairIsInvalidArgument(t *testing.T) {
	t.Parallel()
	fx := startReleaseGRPC(t)
	c := adminv1.NewReleaseAdminServiceClient(fx.conn)
	one := validProto("rel-1", 1)
	one.Frontend = nil
	if _, err := c.Register(context.Background(), &adminv1.RegisterReleaseRequest{Release: one}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestReleaseAdmin_PinUnknownIs404(t *testing.T) {
	t.Parallel()
	fx := startReleaseGRPC(t)
	c := adminv1.NewReleaseAdminServiceClient(fx.conn)
	if _, err := c.Pin(context.Background(), &adminv1.PinReleaseRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}
