package grpcserver_test

// Error / branch coverage for the three Phase A core services (AuditWriter,
// Authorizer, Discovery). The happy-path roundtrips live in
// grpcserver_test.go; this file pins the nil-dependency gates, validation
// rejections, store-error -> codes.Internal mappings, and the proto-conversion
// branches that the roundtrip tests don't reach.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	auditv1 "github.com/yangwb1123/snaplink/gen/proto/audit/v1"
	authzv1 "github.com/yangwb1123/snaplink/gen/proto/authz/v1"
	discoveryv1 "github.com/yangwb1123/snaplink/gen/proto/discovery/v1"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/registry"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// --- erroring stubs ---

// erroringProvider returns a configured error from every Provider method.
// Used to exercise the codes.Internal branches in AuthzService.
type erroringProvider struct{ err error }

func (e *erroringProvider) Permissions(context.Context, string, string) ([]permissions.Permission, error) {
	return nil, e.err
}
func (e *erroringProvider) Roles(context.Context, string, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringProvider) Menus(context.Context, string, string) (permissions.MenuTree, error) {
	return nil, e.err
}
func (e *erroringProvider) AddRole(context.Context, string, permissions.Role) error    { return e.err }
func (e *erroringProvider) UpdateRole(context.Context, string, permissions.Role) error { return e.err }
func (e *erroringProvider) RemoveRole(context.Context, string, string) error           { return e.err }
func (e *erroringProvider) AssignRoles(context.Context, string, string, []string) error {
	return e.err
}
func (e *erroringProvider) UnassignRoles(context.Context, string, string, []string) error {
	return e.err
}
func (e *erroringProvider) SetMenus(context.Context, string, permissions.MenuTree) error {
	return e.err
}
func (e *erroringProvider) ListAllRoles(context.Context, string) ([]permissions.Role, error) {
	return nil, e.err
}
func (e *erroringProvider) ListAssignments(context.Context, string) ([]permissions.Assignment, error) {
	return nil, e.err
}

// erroringRegistry returns a configured error from the read/write methods.
type erroringRegistry struct{ err error }

func (e *erroringRegistry) Register(context.Context, *registry.Service) error { return e.err }
func (e *erroringRegistry) Deregister(context.Context, string) error          { return e.err }
func (e *erroringRegistry) Discover(context.Context, string) ([]*registry.Service, error) {
	return nil, e.err
}
func (e *erroringRegistry) Watch(context.Context, string) (<-chan registry.Event, error) {
	return nil, e.err
}
func (e *erroringRegistry) Close() error { return nil }

// recordingRegistry is a minimal in-memory Registry that captures Register
// and serves Discover from the captured map -- enough to drive the
// proto-conversion branches without the memory package's TTL machinery.
type recordingRegistry struct {
	byName map[string][]*registry.Service
}

func newRecordingRegistry() *recordingRegistry {
	return &recordingRegistry{byName: map[string][]*registry.Service{}}
}

func (r *recordingRegistry) Register(_ context.Context, svc *registry.Service) error {
	r.byName[svc.Name] = append(r.byName[svc.Name], svc)
	return nil
}
func (r *recordingRegistry) Deregister(context.Context, string) error { return nil }
func (r *recordingRegistry) Discover(_ context.Context, name string) ([]*registry.Service, error) {
	svcs, ok := r.byName[name]
	if !ok || len(svcs) == 0 {
		return nil, registry.ErrNotFound
	}
	return svcs, nil
}
func (r *recordingRegistry) Watch(context.Context, string) (<-chan registry.Event, error) {
	ch := make(chan registry.Event)
	close(ch)
	return ch, nil
}
func (r *recordingRegistry) Close() error { return nil }

// --- AuditWriter ---

func TestAudit_StreamEventsWithoutRecorderFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startGRPC(t, nil, nil, nil)
	c := auditv1.NewAuditWriterClient(conn)
	stream, err := c.StreamEvents(context.Background())
	if err != nil {
		t.Fatalf("StreamEvents open: %v", err)
	}
	// The first Send may succeed (buffered) but CloseAndRecv must surface the
	// server-side FailedPrecondition.
	_ = stream.Send(&auditv1.Event{Type: "x"})
	if _, err := stream.CloseAndRecv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("expected FailedPrecondition, got %v", err)
	}
}

func TestAudit_RecordStampsTimestamp(t *testing.T) {
	t.Parallel()
	// Exercises the in.TimestampUnix != 0 branch of protoToEvent and proves
	// the recorder preserves a caller-supplied wall-clock time.
	sink := audit.NewMemorySink(4)
	conn := startGRPC(t, audit.New(sink), nil, nil)
	c := auditv1.NewAuditWriterClient(conn)
	ts := time.Now().Add(-time.Hour).Unix()
	if _, err := c.Record(context.Background(), &auditv1.Event{Type: "login", TimestampUnix: ts}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	evts, _ := sink.Query(context.Background(), audit.Query{Limit: 1})
	if len(evts) != 1 || evts[0].Timestamp.Unix() != ts {
		t.Fatalf("timestamp not preserved: %+v", evts)
	}
}

// --- Authorizer ---

func TestAuthz_NilProviderFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startGRPC(t, nil, nil, nil) // no provider
	c := authzv1.NewAuthorizerClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Check": func() error {
			_, e := c.Check(ctx, &authzv1.CheckRequest{SubjectId: "u", Permission: "p"})
			return e
		},
		"ListPermissions": func() error {
			_, e := c.ListPermissions(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
		"ListRoles": func() error {
			_, e := c.ListRoles(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
		"GetMenus": func() error {
			_, e := c.GetMenus(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, got)
		}
	}
}

func TestAuthz_ListPermissions(t *testing.T) {
	t.Parallel()
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), "web", permissions.Role{
		Code: "admin", Permissions: []string{"user:read", "order:write"},
	})
	_ = prov.AssignRoles(context.Background(), "alice", "web", []string{"admin"})
	conn := startGRPC(t, nil, prov, nil)
	c := authzv1.NewAuthorizerClient(conn)

	resp, err := c.ListPermissions(context.Background(), &authzv1.SubjectRequest{
		SubjectId: "alice", ClientId: "web",
	})
	if err != nil {
		t.Fatalf("ListPermissions: %v", err)
	}
	if len(resp.Permissions) != 2 {
		t.Fatalf("expected 2 permissions, got %+v", resp.Permissions)
	}
}

func TestAuthz_ListPermissions_UnknownUserIsEmptyNotError(t *testing.T) {
	t.Parallel()
	// ErrUserNotFound is swallowed (treated as "no permissions"), not an error.
	prov := permissions.NewMemoryProvider()
	conn := startGRPC(t, nil, prov, nil)
	c := authzv1.NewAuthorizerClient(conn)
	resp, err := c.ListPermissions(context.Background(), &authzv1.SubjectRequest{SubjectId: "ghost", ClientId: "web"})
	if err != nil {
		t.Fatalf("ListPermissions unknown: %v", err)
	}
	if len(resp.Permissions) != 0 {
		t.Fatalf("expected empty, got %+v", resp.Permissions)
	}
}

func TestAuthz_ProviderErrorIsInternal(t *testing.T) {
	t.Parallel()
	prov := &erroringProvider{err: errors.New("db down")}
	conn := startGRPC(t, nil, prov, nil)
	c := authzv1.NewAuthorizerClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Check": func() error {
			_, e := c.Check(ctx, &authzv1.CheckRequest{SubjectId: "u", Permission: "p"})
			return e
		},
		"ListPermissions": func() error {
			_, e := c.ListPermissions(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
		"ListRoles": func() error {
			_, e := c.ListRoles(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
		"GetMenus": func() error {
			_, e := c.GetMenus(ctx, &authzv1.SubjectRequest{SubjectId: "u"})
			return e
		},
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", name, got)
		}
	}
}

func TestAuthz_GetMenusWithButtonsAndChildren(t *testing.T) {
	t.Parallel()
	// Exercises the Buttons and Children branches of convertMenuItem.
	prov := permissions.NewMemoryProvider()
	_ = prov.AddRole(context.Background(), "web", permissions.Role{
		Code: "admin", Permissions: []string{"user:read", "user:create"},
	})
	_ = prov.AssignRoles(context.Background(), "alice", "web", []string{"admin"})
	_ = prov.SetMenus(context.Background(), "web", permissions.MenuTree{
		{
			ID: "m-users", Name: "Users", Permission: "user:read",
			Buttons: []permissions.Button{{Code: "btn-add", Name: "Add", Permission: "user:create"}},
			Children: []permissions.MenuItem{
				{ID: "m-users-list", Name: "List", Permission: "user:read"},
			},
		},
	})
	conn := startGRPC(t, nil, prov, nil)
	c := authzv1.NewAuthorizerClient(conn)
	tree, err := c.GetMenus(context.Background(), &authzv1.SubjectRequest{SubjectId: "alice", ClientId: "web"})
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(tree.Items) != 1 {
		t.Fatalf("expected 1 top item, got %+v", tree.Items)
	}
	top := tree.Items[0]
	if len(top.Buttons) != 1 || top.Buttons[0].Code != "btn-add" {
		t.Errorf("buttons not converted: %+v", top.Buttons)
	}
	if len(top.Children) != 1 || top.Children[0].Id != "m-users-list" {
		t.Errorf("children not converted: %+v", top.Children)
	}
}

// --- Discovery ---

func TestDiscovery_NilRegistryFailsPrecondition(t *testing.T) {
	t.Parallel()
	conn := startGRPC(t, nil, nil, nil)
	c := discoveryv1.NewDiscoveryClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Register": func() error {
			_, e := c.Register(ctx, &discoveryv1.RegisterRequest{Service: &discoveryv1.Service{Id: "s"}})
			return e
		},
		"Deregister": func() error {
			_, e := c.Deregister(ctx, &discoveryv1.DeregisterRequest{InstanceId: "s"})
			return e
		},
		"Discover": func() error {
			_, e := c.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
			return e
		},
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.FailedPrecondition {
			t.Errorf("%s: code = %v, want FailedPrecondition", name, got)
		}
	}
	// Watch is a streaming RPC; the precondition surfaces on first Recv.
	stream, err := c.Watch(ctx, &discoveryv1.WatchRequest{ServiceName: "sso"})
	if err != nil {
		t.Fatalf("Watch open: %v", err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("Watch: expected FailedPrecondition, got %v", err)
	}
}

func TestDiscovery_RegisterNilServiceIsInvalidArgument(t *testing.T) {
	t.Parallel()
	reg := newRecordingRegistry()
	conn := startGRPC(t, nil, nil, reg)
	c := discoveryv1.NewDiscoveryClient(conn)
	if _, err := c.Register(context.Background(), &discoveryv1.RegisterRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestDiscovery_StoreErrorsAreInternal(t *testing.T) {
	t.Parallel()
	reg := &erroringRegistry{err: errors.New("etcd down")}
	conn := startGRPC(t, nil, nil, reg)
	c := discoveryv1.NewDiscoveryClient(conn)
	ctx := context.Background()
	cases := map[string]func() error{
		"Register": func() error {
			_, e := c.Register(ctx, &discoveryv1.RegisterRequest{Service: &discoveryv1.Service{Id: "s", Name: "sso"}})
			return e
		},
		"Deregister": func() error {
			_, e := c.Deregister(ctx, &discoveryv1.DeregisterRequest{InstanceId: "s"})
			return e
		},
		"Discover": func() error {
			_, e := c.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
			return e
		},
	}
	for name, call := range cases {
		if got := status.Code(call()); got != codes.Internal {
			t.Errorf("%s: code = %v, want Internal", name, got)
		}
	}
}

func TestDiscovery_RegisterRoundTripsTTLAndTags(t *testing.T) {
	t.Parallel()
	// Exercises the full protoToService -> registry.Service -> serviceToProto
	// roundtrip, including the TTL/Tags fields the happy-path test omits.
	reg := newRecordingRegistry()
	conn := startGRPC(t, nil, nil, reg)
	c := discoveryv1.NewDiscoveryClient(conn)
	ctx := context.Background()
	if _, err := c.Register(ctx, &discoveryv1.RegisterRequest{Service: &discoveryv1.Service{
		Id: "sso-1", Name: "sso", Address: "10.0.0.1", Port: 9000,
		Tags: []string{"a", "b"}, Version: "v2", TtlSeconds: 45,
	}}); err != nil {
		t.Fatalf("Register: %v", err)
	}
	resp, err := c.Discover(ctx, &discoveryv1.DiscoverRequest{ServiceName: "sso"})
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(resp.Instances) != 1 {
		t.Fatalf("expected 1 instance, got %d", len(resp.Instances))
	}
	got := resp.Instances[0]
	if got.TtlSeconds != 45 || len(got.Tags) != 2 || got.Version != "v2" || got.Port != 9000 {
		t.Errorf("roundtrip mismatch: %+v", got)
	}
}

// compile-time guard that the stubs satisfy the interfaces they impersonate.
var (
	_ permissions.Provider = (*erroringProvider)(nil)
	_ registry.Registry    = (*erroringRegistry)(nil)
	_ registry.Registry    = (*recordingRegistry)(nil)
)
