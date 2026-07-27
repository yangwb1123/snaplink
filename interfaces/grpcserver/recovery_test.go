package grpcserver_test

// Proves the fix for the panic-containment gap: grpc-go installs NO default
// panic recovery (unlike net/http's ServeMux), so a panic inside an
// operator-injected interface implementation (here, permissions.Provider)
// reached through one of this package's thin handlers used to escape the
// RPC and crash the whole server process — taking every other in-flight RPC
// down with it, not just the one call that panicked.

import (
	"context"
	"net"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	"github.com/yangwb1123/snaplink/interfaces/grpcserver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// panickingProvider panics from every Provider method, standing in for a
// buggy or misbehaving operator-supplied permissions backend.
type panickingProvider struct{}

func (panickingProvider) Permissions(context.Context, string, string) ([]permissions.Permission, error) {
	panic("boom: simulated backend panic")
}
func (panickingProvider) Roles(context.Context, string, string) ([]permissions.Role, error) {
	panic("boom")
}
func (panickingProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	panic("boom")
}
func (panickingProvider) AddRole(context.Context, string, permissions.Role) error    { panic("boom") }
func (panickingProvider) UpdateRole(context.Context, string, permissions.Role) error { panic("boom") }
func (panickingProvider) RemoveRole(context.Context, string, string) error           { panic("boom") }
func (panickingProvider) AssignRoles(context.Context, string, string, []string) error {
	panic("boom")
}
func (panickingProvider) UnassignRoles(context.Context, string, string, []string) error {
	panic("boom")
}
func (panickingProvider) SetMenus(context.Context, string, permissions.MenuTree) error {
	panic("boom")
}
func (panickingProvider) ListAllRoles(context.Context, string) ([]permissions.Role, error) {
	panic("boom")
}
func (panickingProvider) ListAssignments(context.Context, string) ([]permissions.Assignment, error) {
	panic("boom")
}

// TestAuthzService_Check_PanicsWithoutRecoveryInterceptor pins the exact
// pre-fix hazard: calling straight into a service handler that delegates to
// a panicking Provider, with nothing recovering it, propagates the panic
// out of Check. In a real grpc.Server, this is the panic that used to reach
// an un-recovered RPC goroutine and crash the whole process. This test
// documents that the raw handler alone provides no protection — the
// protection has to come from the interceptor exercised below.
func TestAuthzService_Check_PanicsWithoutRecoveryInterceptor(t *testing.T) {
	svc := grpcserver.NewAuthzService(panickingProvider{})

	panicked := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				panicked = true
			}
		}()
		_, _ = svc.Check(context.Background(), &authzv1.CheckRequest{SubjectId: "u1", Permission: "p1"})
	}()

	if !panicked {
		t.Fatal("expected the bare handler call to panic (no recovery) — if this stops panicking, RecoveryUnaryServerInterceptor's test below is no longer proving anything")
	}
}

// TestRecoveryUnaryServerInterceptor_ConvertsPanicToInternal wires the same
// panicking Provider behind a real grpc.Server with
// RecoveryUnaryServerInterceptor installed (mirroring cmd/sso-server's
// grpcInterceptorOptions) and proves the panic no longer escapes the RPC:
// the client observes a codes.Internal error, and — critically — the server
// goroutine (and therefore the whole process) survives to serve the next
// call.
func TestRecoveryUnaryServerInterceptor_ConvertsPanicToInternal(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer(grpc.ChainUnaryInterceptor(grpcserver.RecoveryUnaryServerInterceptor(nil)))
	authzv1.RegisterAuthorizerServer(srv, grpcserver.NewAuthzService(panickingProvider{}))
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) { return lis.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := authzv1.NewAuthorizerClient(conn)

	_, err = client.Check(context.Background(), &authzv1.CheckRequest{SubjectId: "u1", Permission: "p1"})
	if err == nil {
		t.Fatal("Check: expected an error from the recovered panic, got nil")
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("Check: status = %v, want codes.Internal", status.Code(err))
	}

	// The server must still be alive: a second, unrelated call succeeds.
	// Pre-fix, the panic would have crashed the whole process here instead.
	if _, err := client.Check(context.Background(), &authzv1.CheckRequest{SubjectId: "u1", Permission: "p1"}); err == nil {
		t.Fatal("second Check: expected another codes.Internal, got nil")
	} else if status.Code(err) != codes.Internal {
		t.Fatalf("second Check: status = %v, want codes.Internal (server should have survived the first panic)", status.Code(err))
	}
}
