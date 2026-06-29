package grpcserver_test

import (
	"context"
	"net"
	"testing"

	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/interfaces/snapshot"
	"github.com/snaplink/sso/interfaces/snapshot/storageinline"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// snapshotFixture wires the source-side stores (the Snapshotter sees these)
// + the destination-side stores (the Restorer applies into these) + an
// in-memory Storage shared by Pipeline. Two independent client/user stores
// let one assertion verify Restore actually moved bytes across.
type snapshotFixture struct {
	srcClients *defaultimpl.MemoryClientStore
	srcUsers   *defaultimpl.MemoryUserProvider
	dstClients *defaultimpl.MemoryClientStore
	dstUsers   *defaultimpl.MemoryUserProvider
	storage    *inline.Storage
	pipeline   *snapshot.Pipeline
	sink       *audit.MemorySink
	conn       *grpc.ClientConn
}

func startSnapshotGRPC(t *testing.T) *snapshotFixture {
	t.Helper()
	src := defaultimpl.NewMemoryClientStore()
	src.AddSeed(&sso.Client{ID: "web-app", Name: "Web", Active: true})
	srcUsers := defaultimpl.NewMemoryUserProvider()
	_ = srcUsers.CreateOrUpdate(context.Background(), &sso.User{ID: "alice", Provider: "password"})

	dst := defaultimpl.NewMemoryClientStore()
	dstUsers := defaultimpl.NewMemoryUserProvider()

	storage := inline.New()
	pipeline := &snapshot.Pipeline{}
	snapper := &snapshot.Snapshotter{Clients: src, Users: srcUsers, Namespace: "sso-server"}
	restorer := &snapshot.Restorer{Clients: dst, Users: dstUsers, Namespace: "sso-server"}

	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterSnapshotAdminServiceServer(srv,
		grpcserver.NewSnapshotAdminService(pipeline, storage, snapper, restorer, rec))
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
	return &snapshotFixture{
		srcClients: src, srcUsers: srcUsers,
		dstClients: dst, dstUsers: dstUsers,
		storage: storage, pipeline: pipeline,
		sink: sink, conn: conn,
	}
}

func TestSnapshotAdmin_FullCycle(t *testing.T) {
	t.Parallel()
	fx := startSnapshotGRPC(t)
	c := adminv1.NewSnapshotAdminServiceClient(fx.conn)
	ctx := context.Background()

	// Export.
	exp, err := c.Export(ctx, &adminv1.ExportSnapshotRequest{SourceNodeId: "node-A"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	if exp.Meta == nil || exp.Meta.SnapshotId == "" {
		t.Fatalf("Export: empty meta %+v", exp)
	}
	if exp.StoredAs != exp.Meta.SnapshotId {
		t.Errorf("StoredAs=%q SnapshotId=%q", exp.StoredAs, exp.Meta.SnapshotId)
	}
	if exp.Meta.SourceNodeId != "node-A" {
		t.Errorf("SourceNodeId=%q", exp.Meta.SourceNodeId)
	}
	if exp.Meta.SizeBytes <= 0 {
		t.Errorf("SizeBytes=%d", exp.Meta.SizeBytes)
	}
	id := exp.Meta.SnapshotId

	// List should surface the freshly-exported entry with header fields
	// populated (body-derived fields stay zero per the documented contract).
	list, err := c.List(ctx, &adminv1.ListSnapshotsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Items) != 1 || list.Items[0].SnapshotId != id {
		t.Fatalf("List items=%+v", list.Items)
	}
	if list.Items[0].Codec == "" || list.Items[0].EncryptionAlgorithm == "" {
		t.Errorf("List header fields empty: %+v", list.Items[0])
	}

	// Get returns the full body — meta.taken_at_unix should now be set.
	got, err := c.Get(ctx, &adminv1.GetSnapshotRequest{Id: id})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Meta.TakenAtUnix == 0 {
		t.Errorf("Get meta TakenAtUnix=0")
	}
	if len(got.ResourcesJson) == 0 {
		t.Errorf("Get resources_json empty")
	}

	// Restore (overwrite) into the destination stores.
	rest, err := c.Restore(ctx, &adminv1.RestoreSnapshotRequest{
		Id:   id,
		Mode: "overwrite",
	})
	if err != nil {
		t.Fatalf("Restore: %v", err)
	}
	if rest.Report == nil || rest.Report.Mode != "overwrite" {
		t.Fatalf("Report=%+v", rest.Report)
	}
	clients := rest.Report.Items[string(snapshot.CategoryClients)]
	if clients == nil || clients.Inserted < 1 {
		t.Errorf("clients inserted=%+v", clients)
	}
	if _, err := fx.dstClients.Get(ctx, "web-app"); err != nil {
		t.Errorf("dst missing client after restore: %v", err)
	}
	if _, err := fx.dstUsers.GetByID(ctx, "alice"); err != nil {
		t.Errorf("dst missing user after restore: %v", err)
	}

	// Delete.
	if _, err := c.Delete(ctx, &adminv1.DeleteSnapshotRequest{Id: id}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	post, _ := c.List(ctx, &adminv1.ListSnapshotsRequest{})
	if len(post.Items) != 0 {
		t.Errorf("after Delete List items=%d", len(post.Items))
	}

	// Audit: Export + Restore + Delete = 3 events.
	if got := fx.sink.Len(); got != 3 {
		t.Errorf("audit events = %d, want 3", got)
	}
	want := map[audit.EventType]bool{
		audit.EventSnapshotExported: false,
		audit.EventSnapshotRestored: false,
		audit.EventSnapshotDeleted:  false,
	}
	events, err := fx.sink.Query(ctx, audit.Query{Limit: 50})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	for _, e := range events {
		if _, ok := want[e.Type]; ok {
			want[e.Type] = true
		}
	}
	for typ, seen := range want {
		if !seen {
			t.Errorf("missing audit event %q", typ)
		}
	}
}

func TestSnapshotAdmin_GetUnknownIs404(t *testing.T) {
	t.Parallel()
	fx := startSnapshotGRPC(t)
	c := adminv1.NewSnapshotAdminServiceClient(fx.conn)
	if _, err := c.Get(context.Background(), &adminv1.GetSnapshotRequest{Id: "ghost"}); status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

func TestSnapshotAdmin_RestoreReplaceWithoutConfirmFailsPrecondition(t *testing.T) {
	t.Parallel()
	fx := startSnapshotGRPC(t)
	c := adminv1.NewSnapshotAdminServiceClient(fx.conn)
	ctx := context.Background()
	exp, err := c.Export(ctx, &adminv1.ExportSnapshotRequest{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	_, err = c.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: exp.Meta.SnapshotId, Mode: "replace"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestSnapshotAdmin_RestoreUnknownModeIsInvalidArgument(t *testing.T) {
	t.Parallel()
	fx := startSnapshotGRPC(t)
	c := adminv1.NewSnapshotAdminServiceClient(fx.conn)
	ctx := context.Background()
	exp, err := c.Export(ctx, &adminv1.ExportSnapshotRequest{})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	_, err = c.Restore(ctx, &adminv1.RestoreSnapshotRequest{Id: exp.Meta.SnapshotId, Mode: "wat"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}
