package grpcserver_test

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	"github.com/snaplink/sso/audit"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/grpcserver"
	"github.com/snaplink/sso/tenant"
	tenantmemory "github.com/snaplink/sso/tenant/memory"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// startTenantAdminGRPC stands up a bufconn-backed gRPC server with the
// TenantAdminService registered. The invalidateCount tracker is the test
// hook that lets us verify SetStatus + Delete fire the cache callback.
func startTenantAdminGRPC(t *testing.T, store tenant.Store, recorder *audit.Recorder, invalidate func(string)) *grpc.ClientConn {
	return startTenantAdminGRPCFull(t, store, recorder, invalidate, nil)
}

// startTenantAdminGRPCFull additionally injects the active-revocation hook
// fired when a tenant is suspended (nil = no-op).
func startTenantAdminGRPCFull(t *testing.T, store tenant.Store, recorder *audit.Recorder, invalidate func(string), revoke func(context.Context, string)) *grpc.ClientConn {
	t.Helper()
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	adminv1.RegisterTenantAdminServiceServer(srv, grpcserver.NewTenantAdminService(store, recorder, invalidate, revoke))
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

func TestTenantAdmin_CRUD(t *testing.T) {
	store := tenantmemory.New()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	conn := startTenantAdminGRPC(t, store, rec, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	// Create
	created, err := c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme", Name: "Acme Inc"},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Tenant.Id != "acme" {
		t.Fatalf("created id: got %q want acme", created.Tenant.Id)
	}
	// Default status applied by Validate.
	if created.Tenant.Status != string(tenant.StatusActive) {
		t.Fatalf("default status: got %q want active", created.Tenant.Status)
	}

	// Duplicate Create rejected.
	if _, err := c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme"},
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("dup create: got code %v want AlreadyExists", status.Code(err))
	}

	// Get
	got, err := c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "acme"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Tenant.Name != "Acme Inc" {
		t.Fatalf("get name: got %q", got.Tenant.Name)
	}

	// List
	list, err := c.ListTenants(ctx, &adminv1.ListTenantsRequest{})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Tenants) != 1 {
		t.Fatalf("list len: %d want 1", len(list.Tenants))
	}

	// Update name
	if _, err := c.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme", Name: "Acme Renamed"},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "acme"})
	if got.Tenant.Name != "Acme Renamed" {
		t.Fatalf("update name: got %q", got.Tenant.Name)
	}

	// Delete
	if _, err := c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "acme"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "acme"}); status.Code(err) != codes.NotFound {
		t.Fatalf("post-delete Get: got code %v want NotFound", status.Code(err))
	}
}

func TestTenantAdmin_UpdatePreservesStatus(t *testing.T) {
	// Update is for non-status fields; the SetStatus RPC is the only
	// path that flips active/suspended. Verify Update on a suspended
	// tenant leaves it suspended.
	store := tenantmemory.New()
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	_, _ = c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: string(tenant.StatusSuspended)})
	_, _ = c.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1", Name: "new name", Status: string(tenant.StatusActive)},
	})
	got, _ := c.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "t1"})
	if got.Tenant.Status != string(tenant.StatusSuspended) {
		t.Fatalf("Update tried to flip status; got %q want suspended", got.Tenant.Status)
	}
}

func TestTenantAdmin_SetStatusFiresCacheInvalidation(t *testing.T) {
	// AGENTS.md invariant: admin SetStatus handlers MUST call
	// (*Server).InvalidateTenantSuspensionCache(id) so the flip
	// takes effect on the next validate. Verify the callback fires.
	store := tenantmemory.New()
	var invalidated atomic.Int32
	var lastID atomic.Value
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), func(id string) {
		invalidated.Add(1)
		lastID.Store(id)
	})
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	if _, err := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{
		Id: "t1", Status: string(tenant.StatusSuspended),
	}); err != nil {
		t.Fatalf("SetStatus: %v", err)
	}
	if invalidated.Load() != 1 {
		t.Fatalf("invalidate count = %d want 1 (post-suspension cache flush)", invalidated.Load())
	}
	if got, _ := lastID.Load().(string); got != "t1" {
		t.Fatalf("invalidated id = %q want t1", got)
	}
}

func TestTenantAdmin_SetStatusNoOpStillInvalidates(t *testing.T) {
	// Even when the flip is a no-op (active → active), invalidate the
	// cache cheaply — a drifted cache shouldn't outlive an explicit
	// admin call.
	store := tenantmemory.New()
	var invalidated atomic.Int32
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), func(string) {
		invalidated.Add(1)
	})
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	if _, err := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{
		Id: "t1", Status: string(tenant.StatusActive),
	}); err != nil {
		t.Fatalf("SetStatus (noop): %v", err)
	}
	if invalidated.Load() < 1 {
		t.Fatal("noop SetStatus must still invalidate cache")
	}
}

func TestTenantAdmin_SuspendFiresTokenRevocation(t *testing.T) {
	// A real flip to Suspended must fire active refresh-token revocation;
	// a subsequent flip back to Active must NOT (only suspension purges).
	store := tenantmemory.New()
	var revoked atomic.Int32
	var lastID atomic.Value
	conn := startTenantAdminGRPCFull(t, store, audit.New(audit.NewMemorySink(10)),
		func(string) {},
		func(_ context.Context, id string) {
			revoked.Add(1)
			lastID.Store(id)
		})
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	if _, err := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{
		Id: "t1", Status: string(tenant.StatusSuspended),
	}); err != nil {
		t.Fatalf("suspend: %v", err)
	}
	if revoked.Load() != 1 {
		t.Fatalf("revoke count = %d want 1 after suspend", revoked.Load())
	}
	if got, _ := lastID.Load().(string); got != "t1" {
		t.Fatalf("revoked tenant = %q want t1", got)
	}

	// Reactivation must not trigger another purge.
	if _, err := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{
		Id: "t1", Status: string(tenant.StatusActive),
	}); err != nil {
		t.Fatalf("reactivate: %v", err)
	}
	if revoked.Load() != 1 {
		t.Fatalf("revoke count = %d want 1 (reactivate must not revoke)", revoked.Load())
	}
}

func TestTenantAdmin_SetStatusValidates(t *testing.T) {
	store := tenantmemory.New()
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	if _, err := c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{
		Id: "t1", Status: "deleted",
	}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bogus status: got %v want InvalidArgument", status.Code(err))
	}
}

func TestTenantAdmin_DeleteInvalidatesCache(t *testing.T) {
	store := tenantmemory.New()
	var invalidated atomic.Int32
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), func(string) {
		invalidated.Add(1)
	})
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	if _, err := c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "t1"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if invalidated.Load() != 1 {
		t.Fatalf("delete must invalidate cache; count = %d", invalidated.Load())
	}
}

func TestTenantAdmin_DomainCRUD(t *testing.T) {
	store := tenantmemory.New()
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(20)), nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	// Need a tenant first.
	if _, err := c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	created, err := c.CreateDomain(ctx, &adminv1.CreateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "auth.acme.com", TenantId: "t1"},
	})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if created.Domain.TenantId != "t1" {
		t.Fatalf("tenant id: got %q", created.Domain.TenantId)
	}

	// Duplicate
	if _, err := c.CreateDomain(ctx, &adminv1.CreateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "auth.acme.com", TenantId: "t1"},
	}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("dup domain: %v", status.Code(err))
	}

	// Get
	got, err := c.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "auth.acme.com"})
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Domain.Hostname != "auth.acme.com" {
		t.Fatalf("get hostname: got %q", got.Domain.Hostname)
	}

	// List by tenant
	list, err := c.ListDomains(ctx, &adminv1.ListDomainsRequest{TenantId: "t1"})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list.Domains) != 1 {
		t.Fatalf("list len: %d", len(list.Domains))
	}

	// Update — flip is_apex
	if _, err := c.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "auth.acme.com", TenantId: "t1", IsApex: true},
	}); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, _ = c.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "auth.acme.com"})
	if !got.Domain.IsApex {
		t.Fatal("UpdateDomain didn't apply is_apex flip")
	}

	// Delete
	if _, err := c.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{Hostname: "auth.acme.com"}); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := c.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "auth.acme.com"}); status.Code(err) != codes.NotFound {
		t.Fatalf("post-delete get: %v", status.Code(err))
	}
}

func TestTenantAdmin_AuditFires(t *testing.T) {
	store := tenantmemory.New()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	conn := startTenantAdminGRPC(t, store, rec, nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	ctx := context.Background()

	_, _ = c.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"},
	})
	_, _ = c.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: string(tenant.StatusSuspended)})
	_, _ = c.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "t1"})

	events, err := sink.Query(ctx, audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	seen := map[audit.EventType]bool{}
	for _, e := range events {
		seen[e.Type] = true
	}
	for _, want := range []audit.EventType{
		audit.EventAdminTenantCreated,
		audit.EventAdminTenantStatusChanged,
		audit.EventAdminTenantDeleted,
	} {
		if !seen[want] {
			t.Errorf("missing audit event %q", want)
		}
	}
}

func TestTenantAdmin_GetNotFound(t *testing.T) {
	store := tenantmemory.New()
	conn := startTenantAdminGRPC(t, store, audit.New(audit.NewMemorySink(10)), nil)
	c := adminv1.NewTenantAdminServiceClient(conn)
	_, err := c.GetTenant(context.Background(), &adminv1.GetTenantRequest{Id: "ghost"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("got code %v want NotFound", status.Code(err))
	}
}
