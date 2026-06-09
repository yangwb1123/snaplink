package grpcserver_test

import (
	"context"
	"net"
	"testing"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/defaultimpl"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/permissions"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startAdminGRPC stands up a bufconn-backed gRPC server with all four admin
// services registered against the supplied stores. Any of clientStore /
// userProvider / sessionMgr / permProvider / tempStore may be nil — the
// corresponding RPCs will respond Unimplemented or FailedPrecondition.
func startAdminGRPC(
	t *testing.T,
	clientStore sso.ClientStore,
	userProvider sso.UserProvider,
	sessionMgr sso.SessionManager,
	permProvider permissions.Provider,
	tempStore authenticators.TempTokenStore,
	recorder *audit.Recorder,
) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterClientAdminServiceServer(srv, grpcserver.NewClientAdminService(clientStore, recorder, nil, nil))
	adminv1.RegisterUserAdminServiceServer(srv, grpcserver.NewUserAdminService(userProvider, sessionMgr, recorder))
	adminv1.RegisterTokenAdminServiceServer(srv, grpcserver.NewTokenAdminService(grpcserver.TokenAdminConfig{
		Sessions:  sessionMgr,
		TempStore: tempStore,
		Recorder:  recorder,
	}))
	adminv1.RegisterPermissionAdminServiceServer(srv, grpcserver.NewPermissionAdminService(permProvider, recorder, nil))
	go func() { _ = srv.Serve(lis) }()

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() {
		conn.Close()
		srv.Stop()
		lis.Close()
	})
	return conn
}

// --- ClientAdmin ---

func TestClientAdmin_CRUD(t *testing.T) {
	store := defaultimpl.NewMemoryClientStore()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	conn := startAdminGRPC(t, store, nil, nil, nil, nil, rec)
	c := adminv1.NewClientAdminServiceClient(conn)
	ctx := context.Background()

	created, err := c.Create(ctx, &adminv1.CreateClientRequest{
		Client: &adminv1.Client{Id: "web-app", Name: "Web", Active: true, AllowedAuthenticators: []string{"password"}},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Client.Id != "web-app" {
		t.Errorf("Create returned %+v", created.Client)
	}

	// Duplicate Create → AlreadyExists.
	if _, err := c.Create(ctx, &adminv1.CreateClientRequest{Client: &adminv1.Client{Id: "web-app"}}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}

	got, err := c.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Client.Name != "Web" {
		t.Errorf("Get returned %+v", got.Client)
	}
	if got.Client.Secret != "" {
		t.Error("Get must not echo secret")
	}

	list, err := c.List(ctx, &adminv1.ListClientsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Clients) != 1 {
		t.Errorf("List len = %d", len(list.Clients))
	}

	_, err = c.Update(ctx, &adminv1.UpdateClientRequest{
		Client: &adminv1.Client{Id: "web-app", Name: "Web v2", Active: true},
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = c.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"})
	if got.Client.Name != "Web v2" {
		t.Errorf("after Update Name=%q", got.Client.Name)
	}

	rot, err := c.RotateSecret(ctx, &adminv1.RotateSecretRequest{Id: "web-app"})
	if err != nil {
		t.Fatalf("RotateSecret: %v", err)
	}
	if len(rot.Secret) < 20 {
		t.Errorf("rotated secret too short: %q", rot.Secret)
	}

	_, err = c.Delete(ctx, &adminv1.DeleteClientRequest{Id: "web-app"})
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, &adminv1.GetClientRequest{Id: "web-app"}); status.Code(err) != codes.NotFound {
		t.Fatalf("after Delete: expected NotFound, got %v", err)
	}

	// Audit: 4 mutations (Create, Update, RotateSecret, Delete).
	if got := sink.Len(); got != 4 {
		t.Errorf("expected 4 admin audit events, got %d", got)
	}
}

func TestClientAdmin_UpdateUnknownIs404(t *testing.T) {
	conn := startAdminGRPC(t, defaultimpl.NewMemoryClientStore(), nil, nil, nil, nil, nil)
	c := adminv1.NewClientAdminServiceClient(conn)
	_, err := c.Update(context.Background(), &adminv1.UpdateClientRequest{Client: &adminv1.Client{Id: "ghost"}})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("expected NotFound, got %v", err)
	}
}

// --- UserAdmin ---

func TestUserAdmin_CRUDAndSessions(t *testing.T) {
	users := defaultimpl.NewMemoryUserProvider()
	sessions := defaultimpl.NewMemorySessionManager()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	conn := startAdminGRPC(t, nil, users, sessions, nil, nil, rec)
	c := adminv1.NewUserAdminServiceClient(conn)
	ctx := context.Background()

	if _, err := c.Create(ctx, &adminv1.CreateUserRequest{
		User: &adminv1.User{Id: "alice", Provider: "password"},
	}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Duplicate.
	if _, err := c.Create(ctx, &adminv1.CreateUserRequest{User: &adminv1.User{Id: "alice"}}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}

	list, _ := c.List(ctx, &adminv1.ListUsersRequest{})
	if len(list.Users) != 1 {
		t.Errorf("List len = %d", len(list.Users))
	}

	// Seed a session for alice.
	_, _ = sessions.Create(ctx, "alice")
	resp, err := c.ListUserSessions(ctx, &adminv1.ListUserSessionsRequest{Id: "alice"})
	if err != nil {
		t.Fatalf("ListUserSessions: %v", err)
	}
	if len(resp.Sessions) != 1 {
		t.Errorf("expected 1 session, got %d", len(resp.Sessions))
	}

	if _, err := c.Delete(ctx, &adminv1.DeleteUserRequest{Id: "alice"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.Get(ctx, &adminv1.GetUserRequest{Id: "alice"}); status.Code(err) != codes.NotFound {
		t.Fatalf("after Delete: expected NotFound, got %v", err)
	}
}

// --- TokenAdmin ---

func TestTokenAdmin_ListAndIssueTemp(t *testing.T) {
	sessions := defaultimpl.NewMemorySessionManager()
	tempStore := authenticators.NewMemoryTempTokenStore()
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	conn := startAdminGRPC(t, nil, nil, sessions, nil, tempStore, rec)
	c := adminv1.NewTokenAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = sessions.Create(ctx, "alice")
	_, _ = sessions.Create(ctx, "bob")

	// All.
	all, err := c.ListSessions(ctx, &adminv1.ListSessionsRequest{})
	if err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if len(all.Sessions) != 2 {
		t.Errorf("expected 2, got %d", len(all.Sessions))
	}
	// Filter by user.
	byUser, _ := c.ListSessions(ctx, &adminv1.ListSessionsRequest{UserId: "alice"})
	if len(byUser.Sessions) != 1 || byUser.Sessions[0].UserId != "alice" {
		t.Errorf("expected 1 alice session, got %+v", byUser.Sessions)
	}

	// IssueTempToken.
	resp, err := c.IssueTempToken(ctx, &adminv1.IssueTempTokenRequest{UserId: "alice", ClientId: "web-app"})
	if err != nil {
		t.Fatalf("IssueTempToken: %v", err)
	}
	if len(resp.Token) < 20 {
		t.Errorf("token too short: %q", resp.Token)
	}
	// Consume to prove it landed in the store.
	if sub, err := tempStore.Consume(ctx, resp.Token); err != nil {
		t.Fatalf("Consume: %v", err)
	} else if sub.ID != "alice" {
		t.Errorf("subject = %+v", sub)
	}

	// Revoke by session id.
	listed, _ := c.ListSessions(ctx, &adminv1.ListSessionsRequest{UserId: "bob"})
	sid := listed.Sessions[0].Id
	rev, err := c.Revoke(ctx, &adminv1.RevokeRequest{SessionId: sid})
	if err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if len(rev.Revoked) == 0 {
		t.Error("expected at least one revoked tag")
	}
}

func TestTokenAdmin_RevokeRequiresIdentifier(t *testing.T) {
	conn := startAdminGRPC(t, nil, nil, defaultimpl.NewMemorySessionManager(), nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	if _, err := c.Revoke(context.Background(), &adminv1.RevokeRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestTokenAdmin_NoSessionsWhenManagerNil(t *testing.T) {
	conn := startAdminGRPC(t, nil, nil, nil, nil, nil, nil)
	c := adminv1.NewTokenAdminServiceClient(conn)
	if _, err := c.ListSessions(context.Background(), &adminv1.ListSessionsRequest{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("expected Unimplemented, got %v", err)
	}
}

// --- PermissionAdmin ---

func TestPermissionAdmin_FullLifecycle(t *testing.T) {
	prov := permissions.NewMemoryProvider()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	conn := startAdminGRPC(t, nil, nil, nil, prov, nil, rec)
	c := adminv1.NewPermissionAdminServiceClient(conn)
	ctx := context.Background()

	// AddRole.
	if _, err := c.AddRole(ctx, &adminv1.AddRoleRequest{
		ClientId: "web", Role: &adminv1.Role{Code: "admin", Permissions: []string{"user:*"}},
	}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	// Duplicate.
	if _, err := c.AddRole(ctx, &adminv1.AddRoleRequest{
		ClientId: "web", Role: &adminv1.Role{Code: "admin"},
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("expected AlreadyExists, got %v", err)
	}

	// ListRoles.
	list, _ := c.ListRoles(ctx, &adminv1.ListRolesRequest{ClientId: "web"})
	if len(list.Roles) != 1 || list.Roles[0].Code != "admin" {
		t.Errorf("ListRoles = %+v", list.Roles)
	}

	// AssignRoles.
	if _, err := c.AssignRoles(ctx, &adminv1.AssignRolesRequest{
		ClientId: "web", UserId: "alice", Roles: []string{"admin"},
	}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	assignments, _ := c.ListAssignments(ctx, &adminv1.ListAssignmentsRequest{ClientId: "web"})
	if len(assignments.Assignments) != 1 || assignments.Assignments[0].UserId != "alice" {
		t.Errorf("ListAssignments = %+v", assignments.Assignments)
	}

	// UpdateRole.
	if _, err := c.UpdateRole(ctx, &adminv1.UpdateRoleRequest{
		ClientId: "web", Role: &adminv1.Role{Code: "admin", Name: "Admin v2", Permissions: []string{"user:*", "order:*"}},
	}); err != nil {
		t.Fatalf("UpdateRole: %v", err)
	}
	// UnassignRoles.
	if _, err := c.UnassignRoles(ctx, &adminv1.UnassignRolesRequest{
		ClientId: "web", UserId: "alice", Roles: []string{"admin"},
	}); err != nil {
		t.Fatalf("UnassignRoles: %v", err)
	}

	// SetMenus.
	if _, err := c.SetMenus(ctx, &adminv1.SetMenusRequest{
		ClientId: "web",
		Menus: []*adminv1.MenuItem{
			{Id: "m-users", Name: "Users", Permission: "user:read"},
		},
	}); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}

	// RemoveRole.
	if _, err := c.RemoveRole(ctx, &adminv1.RemoveRoleRequest{ClientId: "web", RoleCode: "admin"}); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if _, err := c.RemoveRole(ctx, &adminv1.RemoveRoleRequest{ClientId: "web", RoleCode: "admin"}); status.Code(err) != codes.NotFound {
		t.Fatalf("second RemoveRole: expected NotFound, got %v", err)
	}

	// Audit should have many entries (AddRole, AssignRoles, UpdateRole, UnassignRoles, SetMenus, RemoveRole).
	if got := sink.Len(); got != 6 {
		t.Errorf("expected 6 audit events, got %d", got)
	}
}
