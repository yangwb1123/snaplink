package grpcserver_test

// In-process gRPC tests using grpc.NewServer + bufconn. No real port; the
// listener is an in-memory pipe. Verifies the three Phase A services
// roundtrip correctly through the wire format.

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	discoveryv1 "github.com/snaplink/sso/gen/proto/discovery/v1"
	"github.com/snaplink/sso/interfaces/grpcserver"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/registry"
	"github.com/snaplink/sso/platform/registry/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startGRPC stands up an in-memory gRPC server with all three services and
// returns a connected client conn plus a cleanup function.
func startGRPC(t *testing.T, recorder *audit.Recorder, prov permissions.Provider, reg registry.Registry) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)

	srv := grpc.NewServer()
	auditv1.RegisterAuditWriterServer(srv, grpcserver.NewAuditService(recorder))
	authzv1.RegisterAuthorizerServer(srv, grpcserver.NewAuthzService(prov))
	discoveryv1.RegisterDiscoveryServer(srv, grpcserver.NewDiscoveryService(reg))

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
	})
	return conn
}

// --- AuditWriter ---

func TestAudit_Record(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(10)
	recorder := audit.New(sink)
	conn := startGRPC(t, recorder, nil, nil)
	client := auditv1.NewAuditWriterClient(conn)

	ack, err := client.Record(context.Background(), &auditv1.Event{
		Type:    "login",
		Outcome: "success",
		ActorId: "alice",
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	if ack.Id == "" {
		t.Errorf("ack should carry assigned id")
	}
	if got := sink.Len(); got != 1 {
		t.Errorf("sink len = %d, want 1", got)
	}
}

func TestAudit_StreamEvents(t *testing.T) {
	t.Parallel()
	sink := audit.NewMemorySink(100)
	recorder := audit.New(sink)
	conn := startGRPC(t, recorder, nil, nil)
	client := auditv1.NewAuditWriterClient(conn)

	stream, err := client.StreamEvents(context.Background())
	if err != nil {
		t.Fatalf("StreamEvents: %v", err)
	}
	for i := range 5 {
		if err := stream.Send(&auditv1.Event{
			Type: "gateway_request", Outcome: "success",
			RequestId: "req-" + string(rune('a'+i)),
		}); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	ack, err := stream.CloseAndRecv()
	if err != nil {
		t.Fatalf("CloseAndRecv: %v", err)
	}
	if ack.ReceivedCount != 5 || ack.PersistedCount != 5 {
		t.Errorf("ack = %+v, want 5/5", ack)
	}
	if got := sink.Len(); got != 5 {
		t.Errorf("sink len = %d, want 5", got)
	}
}

func TestAudit_RecordWithoutRecorderFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startGRPC(t, nil, nil, nil)
	client := auditv1.NewAuditWriterClient(conn)
	_, err := client.Record(context.Background(), &auditv1.Event{Type: "x"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

// --- Authorizer ---

func newAuthzFixture(t *testing.T) (*memory.Registry, permissions.Provider) {
	t.Helper()
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), "web-app", permissions.Role{Code: "admin", Permissions: []string{"user:*", "order:read"}})
	_ = prov.SetMenus(context.Background(), "web-app", permissions.MenuTree{
		{ID: "m-users", Name: "Users", Permission: "user:read"},
		{ID: "m-audit", Name: "Audit", Permission: "audit:read"}, // not held
	})
	_ = prov.AssignRoles(context.Background(), "user-alice", "web-app", []string{"admin"})
	return memory.New(), prov
}

func TestAuthz_Check_Allowed(t *testing.T) {
	t.Parallel()
	reg, prov := newAuthzFixture(t)
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, prov, reg)
	client := authzv1.NewAuthorizerClient(conn)

	resp, err := client.Check(context.Background(), &authzv1.CheckRequest{
		SubjectId: "user-alice", ClientId: "web-app", Permission: "user:read",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !resp.Allowed {
		t.Fatal("expected allowed=true via user:* wildcard")
	}
}

func TestAuthz_Check_Denied(t *testing.T) {
	t.Parallel()
	reg, prov := newAuthzFixture(t)
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, prov, reg)
	client := authzv1.NewAuthorizerClient(conn)

	resp, err := client.Check(context.Background(), &authzv1.CheckRequest{
		SubjectId: "user-alice", ClientId: "web-app", Permission: "audit:read",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Allowed {
		t.Fatal("expected allowed=false")
	}
}

func TestAuthz_Check_RequiredFieldsValidated(t *testing.T) {
	t.Parallel()
	reg, prov := newAuthzFixture(t)
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, prov, reg)
	client := authzv1.NewAuthorizerClient(conn)

	_, err := client.Check(context.Background(), &authzv1.CheckRequest{
		ClientId: "web-app", Permission: "user:read", // SubjectId missing
	})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestAuthz_GetMenus_FilteredByPermissions(t *testing.T) {
	t.Parallel()
	reg, prov := newAuthzFixture(t)
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, prov, reg)
	client := authzv1.NewAuthorizerClient(conn)

	tree, err := client.GetMenus(context.Background(), &authzv1.SubjectRequest{
		SubjectId: "user-alice", ClientId: "web-app",
	})
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	ids := make([]string, 0, len(tree.Items))
	for _, m := range tree.Items {
		ids = append(ids, m.Id)
	}
	if len(ids) != 1 || ids[0] != "m-users" {
		t.Fatalf("expected only m-users (audit pruned), got %v", ids)
	}
}

func TestAuthz_ListRoles(t *testing.T) {
	t.Parallel()
	reg, prov := newAuthzFixture(t)
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, prov, reg)
	client := authzv1.NewAuthorizerClient(conn)

	roles, err := client.ListRoles(context.Background(), &authzv1.SubjectRequest{
		SubjectId: "user-alice", ClientId: "web-app",
	})
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles.Roles) != 1 || roles.Roles[0].Code != "admin" {
		t.Fatalf("got %+v", roles.Roles)
	}
}

// --- Discovery ---

func TestDiscovery_RegisterDiscoverDeregister(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, nil, reg)
	client := discoveryv1.NewDiscoveryClient(conn)
	ctx := context.Background()

	_, err := client.Register(ctx, &discoveryv1.RegisterRequest{
		Service: &discoveryv1.Service{Id: "sso-1", Name: "sso", Address: "127.0.0.1", Port: 8080},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	resp, err := client.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(resp.Instances) != 1 || resp.Instances[0].Id != "sso-1" {
		t.Fatalf("Discover = %+v", resp.Instances)
	}

	_, err = client.Deregister(ctx, &discoveryv1.DeregisterRequest{InstanceId: "sso-1"})
	if err != nil {
		t.Fatalf("Deregister: %v", err)
	}

	_, err = client.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound after deregister, got %v", err)
	}
}

func TestDiscovery_Watch_StreamsAddedAndRemoved(t *testing.T) {
	t.Parallel()
	reg := memory.New()
	defer func() { _ = reg.Close() }()
	conn := startGRPC(t, nil, nil, reg)
	client := discoveryv1.NewDiscoveryClient(conn)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stream, err := client.Watch(ctx, &discoveryv1.WatchRequest{ServiceName: "sso"})
	if err != nil {
		t.Fatalf("Watch: %v", err)
	}
	// Block until the server flushes its initial headers — guarantees the
	// subscription is live before we start mutating.
	if _, err := stream.Header(); err != nil {
		t.Fatalf("stream header: %v", err)
	}

	// Run register/deregister concurrently with the receiving loop.
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = client.Register(context.Background(), &discoveryv1.RegisterRequest{
			Service: &discoveryv1.Service{Id: "sso-1", Name: "sso"},
		})
		_, _ = client.Deregister(context.Background(), &discoveryv1.DeregisterRequest{InstanceId: "sso-1"})
	}()

	added, err := recvWithTimeout(stream)
	if err != nil {
		t.Fatalf("recv added: %v", err)
	}
	if added.Type != discoveryv1.EventType_EVENT_TYPE_ADDED {
		t.Errorf("expected ADDED, got %v", added.Type)
	}

	removed, err := recvWithTimeout(stream)
	if err != nil {
		t.Fatalf("recv removed: %v", err)
	}
	if removed.Type != discoveryv1.EventType_EVENT_TYPE_REMOVED {
		t.Errorf("expected REMOVED, got %v", removed.Type)
	}

	<-done
	cancel()
}

func recvWithTimeout(stream grpc.ServerStreamingClient[discoveryv1.ServiceEvent]) (*discoveryv1.ServiceEvent, error) {
	type result struct {
		evt *discoveryv1.ServiceEvent
		err error
	}
	ch := make(chan result, 1)
	go func() {
		evt, err := stream.Recv()
		ch <- result{evt, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil && !errors.Is(r.err, io.EOF) {
			return nil, r.err
		}
		return r.evt, nil
	case <-time.After(2 * time.Second):
		return nil, errors.New("timeout waiting for stream event")
	}
}
