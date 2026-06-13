package remote_test

import (
	"context"
	"net"
	"testing"

	"github.com/snaplink/sso/audit"
	auditv1 "github.com/snaplink/sso/gen/proto/audit/v1"
	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ssoclient"
	"github.com/snaplink/sso/ssoclient/remote"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// startGRPCBackend stands up Authorizer + AuditWriter inside an in-memory
// gRPC server and returns a *grpc.ClientConn pointing at it.
func startGRPCBackend(t *testing.T, prov permissions.Provider, recorder *audit.Recorder) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	authzv1.RegisterAuthorizerServer(srv, grpcserver.NewAuthzService(prov))
	auditv1.RegisterAuditWriterServer(srv, grpcserver.NewAuditService(recorder))
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
	return conn
}

// Interface satisfaction guards.
var (
	_ ssoclient.AuthzClient = (*remote.AuthzClient)(nil)
	_ ssoclient.AuditClient = (*remote.AuditClient)(nil)
)

// --- AuthzClient ---

func authzProvider(t *testing.T) permissions.Provider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	if err := p.AddRole(context.Background(), "web-app", permissions.Role{Code: "admin", Permissions: []string{"user:*"}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := p.SetMenus(context.Background(), "web-app", permissions.MenuTree{
		{ID: "m-users", Permission: "user:read"},
		{ID: "m-audit", Permission: "audit:read"},
	}); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}
	if err := p.AssignRoles(context.Background(), "user-alice", "web-app", []string{"admin"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	return p
}

func TestRemoteAuthz_CheckAllowed(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)

	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "user:read",
	})
	if err != nil || !ok {
		t.Fatalf("expected allowed; ok=%v err=%v", ok, err)
	}
}

func TestRemoteAuthz_CheckDenied(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)

	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "audit:read",
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if ok {
		t.Fatal("expected denied")
	}
}

func TestRemoteAuthz_CheckNilRequestErrors(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)
	if _, err := c.Check(context.Background(), nil); err == nil {
		t.Fatal("nil request should error")
	}
}

func TestRemoteAuthz_GetMenusFiltered(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)
	tree, err := c.GetMenus(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(tree) != 1 || tree[0].ID != "m-users" {
		t.Fatalf("expected [m-users], got %+v", tree)
	}
}

func TestRemoteAuthz_ListPermissions(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)
	perms, err := c.ListPermissions(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(perms) != 1 || perms[0].Code != "user:*" {
		t.Fatalf("got %+v", perms)
	}
}

func TestRemoteAuthz_ListRoles(t *testing.T) {
	conn := startGRPCBackend(t, authzProvider(t), nil)
	c := remote.NewAuthzClient(conn)
	roles, err := c.ListRoles(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(roles) != 1 || roles[0].Code != "admin" {
		t.Fatalf("got %+v", roles)
	}
}

// --- AuditClient ---

func TestRemoteAudit_Record(t *testing.T) {
	sink := audit.NewMemorySink(10)
	recorder := audit.New(sink)
	conn := startGRPCBackend(t, nil, recorder)
	c := remote.NewAuditClient(conn)

	if err := c.Record(context.Background(), &ssoclient.Event{
		Type: audit.EventLogin, ActorID: "alice",
	}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if sink.Len() != 1 {
		t.Fatalf("sink len = %d, want 1", sink.Len())
	}
}

func TestRemoteAudit_RecordNilErrors(t *testing.T) {
	conn := startGRPCBackend(t, nil, audit.New(audit.NewMemorySink(1)))
	c := remote.NewAuditClient(conn)
	if err := c.Record(context.Background(), nil); err == nil {
		t.Fatal("nil event should error")
	}
}

func TestRemoteAudit_CloseIsNoop(t *testing.T) {
	conn := startGRPCBackend(t, nil, audit.New(audit.NewMemorySink(1)))
	c := remote.NewAuditClient(conn)
	if err := c.Close(); err != nil {
		t.Errorf("Close should be no-op: %v", err)
	}
}
