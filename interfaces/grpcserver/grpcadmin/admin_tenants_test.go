package grpcadmin

import (
	"context"
	"testing"

	"github.com/snaplink/sso/domains/tenant"
	tenantmemory "github.com/snaplink/sso/domains/tenant/memory"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
	"google.golang.org/grpc/codes"
)

// tenantCallbacks captures the three optional hook invocations
// (invalidateSuspensionCache / invalidateResidencyCache / revokeTenantTokens)
// so tests can assert exactly when the server-side cache-eviction +
// active-revocation machinery fires, without needing the real *sso.Server.
type tenantCallbacks struct {
	invalidatedSuspension []string
	invalidatedResidency  []string
	revokedTenants        []string
}

func newTenantAdminServiceForTest(store tenant.Store, rec *audit.Recorder) (*TenantAdminService, *tenantCallbacks) {
	cb := &tenantCallbacks{}
	svc := NewTenantAdminService(store, rec,
		func(id string) { cb.invalidatedSuspension = append(cb.invalidatedSuspension, id) },
		func(id string) { cb.invalidatedResidency = append(cb.invalidatedResidency, id) },
		func(_ context.Context, id string) { cb.revokedTenants = append(cb.revokedTenants, id) },
	)
	return svc, cb
}

// TestTenantAdminService_NilStorePreconditionFails proves every RPC returns
// FailedPrecondition when the store dependency is unwired.
func TestTenantAdminService_NilStorePreconditionFails(t *testing.T) {
	t.Parallel()
	svc := NewTenantAdminService(nil, nil, nil, nil, nil)
	ctx := context.Background()

	_, err := svc.ListTenants(ctx, &adminv1.ListTenantsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "x", Slug: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{Tenant: &adminv1.Tenant{Id: "x", Slug: "x"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "x", Status: string(tenant.StatusActive)})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.ListDomains(ctx, &adminv1.ListDomainsRequest{})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "x"})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.CreateDomain(ctx, &adminv1.CreateDomainRequest{Domain: &adminv1.Domain{Hostname: "x", TenantId: "t"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{Domain: &adminv1.Domain{Hostname: "x", TenantId: "t"}})
	requireCode(t, err, codes.FailedPrecondition)
	_, err = svc.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{Hostname: "x"})
	requireCode(t, err, codes.FailedPrecondition)
}

// TestTenantAdminService_CRUD drives Create/Get/List/Update/Delete directly,
// proving Update preserves Status (a status flip must go through
// SetTenantStatus, never piggyback on Update) and Delete fires every
// cleanup callback (suspension cache, residency cache, token revocation).
func TestTenantAdminService_CRUD(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	svc, cb := newTenantAdminServiceForTest(store, rec)
	ctx := context.Background()

	created, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme", Name: "Acme Inc"},
	})
	requireOK(t, err, "CreateTenant")
	if created.Tenant.Status != string(tenant.StatusActive) {
		t.Errorf("expected default Status=active, got %q", created.Tenant.Status)
	}
	if len(cb.invalidatedResidency) != 0 {
		t.Errorf("expected no residency invalidation for a no-residency create, got %v", cb.invalidatedResidency)
	}

	_, err = svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme"}})
	requireCode(t, err, codes.AlreadyExists)

	_, err = svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "no-slug"}})
	requireCode(t, err, codes.InvalidArgument)

	// A garbage status must be rejected here exactly like SetTenantStatus
	// rejects one (see TestTenantAdminService_SetTenantStatus) — Create is
	// the other path that can set Status, so it needs the same allowlist.
	_, err = svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "bogus-status", Slug: "bogus-status", Status: "bogus"},
	})
	requireCode(t, err, codes.InvalidArgument)
	if _, getErr := svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "bogus-status"}); getErr == nil {
		t.Error("CreateTenant with an invalid status must not persist the tenant")
	}

	got, err := svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "acme"})
	requireOK(t, err, "GetTenant")
	if got.Tenant.Name != "Acme Inc" {
		t.Errorf("GetTenant Name = %q", got.Tenant.Name)
	}
	_, err = svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "missing"})
	requireCode(t, err, codes.NotFound)

	list, err := svc.ListTenants(ctx, &adminv1.ListTenantsRequest{})
	requireOK(t, err, "ListTenants")
	if len(list.Tenants) != 1 {
		t.Errorf("ListTenants len = %d", len(list.Tenants))
	}

	// Update must not be able to sneak a status flip in.
	updated, err := svc.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "acme", Slug: "acme", Name: "Acme Corp", Status: string(tenant.StatusSuspended)},
	})
	requireOK(t, err, "UpdateTenant")
	if updated.Tenant.Status != string(tenant.StatusActive) {
		t.Errorf("Update must preserve existing Status, got %q", updated.Tenant.Status)
	}
	if len(cb.invalidatedResidency) != 1 {
		t.Errorf("expected Update to unconditionally invalidate residency cache, got %v", cb.invalidatedResidency)
	}

	_, err = svc.UpdateTenant(ctx, &adminv1.UpdateTenantRequest{Tenant: &adminv1.Tenant{Id: "missing", Slug: "x"}})
	requireCode(t, err, codes.NotFound)

	_, err = svc.DeleteTenant(ctx, &adminv1.DeleteTenantRequest{Id: "acme"})
	requireOK(t, err, "DeleteTenant")
	if len(cb.invalidatedSuspension) != 1 || len(cb.invalidatedResidency) != 2 || len(cb.revokedTenants) != 1 {
		t.Errorf("expected Delete to fire all three cleanup hooks once, got %+v", cb)
	}
	_, err = svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "acme"})
	requireCode(t, err, codes.NotFound)
}

// TestTenantAdminService_CreateWithResidencyInvalidatesCache proves the
// hasResidency guard: a Create that DOES set a residency field must fire
// invalidateResidencyCache (unlike the common no-residency create above).
func TestTenantAdminService_CreateWithResidencyInvalidatesCache(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	svc, cb := newTenantAdminServiceForTest(store, nil)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{
		Tenant: &adminv1.Tenant{Id: "eu-co", Slug: "eu-co", HomeRegion: " eu-west "},
	})
	requireOK(t, err, "CreateTenant with residency")
	if len(cb.invalidatedResidency) != 1 || cb.invalidatedResidency[0] != "eu-co" {
		t.Errorf("expected residency invalidation for eu-co, got %v", cb.invalidatedResidency)
	}
	got, _ := svc.GetTenant(ctx, &adminv1.GetTenantRequest{Id: "eu-co"})
	if got.Tenant.HomeRegion != "eu-west" {
		t.Errorf("expected HomeRegion to be trimmed to %q, got %q", "eu-west", got.Tenant.HomeRegion)
	}
}

// TestTenantAdminService_SetTenantStatus covers the suspend/activate/no-op
// flip paths: suspend fires token revocation, activate does not, and a
// same-status no-op flip still refreshes the suspension cache without
// writing an audit event or revoking anything.
func TestTenantAdminService_SetTenantStatus(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	svc, cb := newTenantAdminServiceForTest(store, rec)
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"}})
	requireOK(t, err, "CreateTenant")

	_, err = svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: "bogus"})
	requireCode(t, err, codes.InvalidArgument)

	_, err = svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "missing", Status: string(tenant.StatusSuspended)})
	requireCode(t, err, codes.NotFound)

	// No-op flip (already active -> active): cache refresh, no revoke, no audit.
	_, err = svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: string(tenant.StatusActive)})
	requireOK(t, err, "no-op SetTenantStatus")
	if len(cb.invalidatedSuspension) != 1 || len(cb.revokedTenants) != 0 {
		t.Errorf("no-op flip: expected 1 cache refresh and 0 revokes, got %+v", cb)
	}

	// Real flip to Suspended: revoke fires.
	resp, err := svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: string(tenant.StatusSuspended)})
	requireOK(t, err, "SetTenantStatus suspend")
	if resp.Tenant.Status != string(tenant.StatusSuspended) {
		t.Errorf("expected Status=suspended, got %q", resp.Tenant.Status)
	}
	if len(cb.revokedTenants) != 1 || cb.revokedTenants[0] != "t1" {
		t.Errorf("expected suspend to revoke t1's tokens, got %v", cb.revokedTenants)
	}

	// Flip back to Active: no additional revoke.
	_, err = svc.SetTenantStatus(ctx, &adminv1.SetTenantStatusRequest{Id: "t1", Status: string(tenant.StatusActive)})
	requireOK(t, err, "SetTenantStatus activate")
	if len(cb.revokedTenants) != 1 {
		t.Errorf("expected activation to NOT revoke tokens, got %v", cb.revokedTenants)
	}

	events, err := sink.Query(ctx, audit.Query{Type: audit.EventAdminTenantStatusChanged})
	requireOK(t, err, "sink.Query")
	if len(events) != 2 { // suspend + re-activate; the no-op flip records nothing
		t.Errorf("expected 2 status-change audit events, got %d", len(events))
	}
}

// TestTenantAdminService_DomainCRUD drives the domain sub-resource RPCs,
// including the tenant-scoped ListDomains filter.
func TestTenantAdminService_DomainCRUD(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	svc, _ := newTenantAdminServiceForTest(store, nil)
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"}})
	requireOK(t, err, "CreateTenant")

	created, err := svc.CreateDomain(ctx, &adminv1.CreateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "app.example.com", TenantId: "t1", IsApex: true},
	})
	requireOK(t, err, "CreateDomain")
	if created.Domain.TenantId != "t1" {
		t.Errorf("CreateDomain response = %+v", created.Domain)
	}

	_, err = svc.CreateDomain(ctx, &adminv1.CreateDomainRequest{Domain: &adminv1.Domain{Hostname: "app.example.com", TenantId: "t1"}})
	requireCode(t, err, codes.AlreadyExists)

	got, err := svc.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "app.example.com"})
	requireOK(t, err, "GetDomain")
	if !got.Domain.IsApex {
		t.Error("GetDomain lost IsApex")
	}
	_, err = svc.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "missing.example.com"})
	requireCode(t, err, codes.NotFound)

	listAll, err := svc.ListDomains(ctx, &adminv1.ListDomainsRequest{})
	requireOK(t, err, "ListDomains all")
	if len(listAll.Domains) != 1 {
		t.Errorf("ListDomains all len = %d", len(listAll.Domains))
	}
	listScoped, err := svc.ListDomains(ctx, &adminv1.ListDomainsRequest{TenantId: "t1"})
	requireOK(t, err, "ListDomains scoped")
	if len(listScoped.Domains) != 1 {
		t.Errorf("ListDomains scoped len = %d", len(listScoped.Domains))
	}
	listOther, err := svc.ListDomains(ctx, &adminv1.ListDomainsRequest{TenantId: "other"})
	requireOK(t, err, "ListDomains other tenant")
	if len(listOther.Domains) != 0 {
		t.Errorf("ListDomains for an unrelated tenant should be empty, got %+v", listOther.Domains)
	}

	_, err = svc.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{Domain: &adminv1.Domain{Hostname: "missing.example.com", TenantId: "t1"}})
	requireCode(t, err, codes.NotFound)
	_, err = svc.UpdateDomain(ctx, &adminv1.UpdateDomainRequest{
		Domain: &adminv1.Domain{Hostname: "app.example.com", TenantId: "t1", IsApex: false},
	})
	requireOK(t, err, "UpdateDomain")
	got, _ = svc.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "app.example.com"})
	if got.Domain.IsApex {
		t.Error("UpdateDomain did not apply IsApex=false")
	}

	_, err = svc.DeleteDomain(ctx, &adminv1.DeleteDomainRequest{Hostname: "app.example.com"})
	requireOK(t, err, "DeleteDomain")
	_, err = svc.GetDomain(ctx, &adminv1.GetDomainRequest{Hostname: "app.example.com"})
	requireCode(t, err, codes.NotFound)
}

// TestTenantAdminService_ListTenantsPagination proves ListTenants actually
// bounds its response by page_size (default sort is id ascending), that the
// returned next_page_token round-trips to the remaining page, and that a
// garbage page_token is rejected — the regression coverage for a List RPC
// that used to ignore page_token/page_size/order_by/filter entirely and
// return every row unbounded.
func TestTenantAdminService_ListTenantsPagination(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	svc, _ := newTenantAdminServiceForTest(store, nil)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c"} {
		_, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: id, Slug: id}})
		requireOK(t, err, "CreateTenant "+id)
	}

	page1, err := svc.ListTenants(ctx, &adminv1.ListTenantsRequest{PageSize: 2})
	requireOK(t, err, "ListTenants page1")
	if len(page1.Tenants) != 2 || page1.TotalSize != 3 || page1.NextPageToken == "" {
		t.Fatalf("page1 = len=%d total=%d next=%q", len(page1.Tenants), page1.TotalSize, page1.NextPageToken)
	}
	if page1.Tenants[0].Id != "a" || page1.Tenants[1].Id != "b" {
		t.Errorf("page1 ids = [%s, %s], want [a, b]", page1.Tenants[0].Id, page1.Tenants[1].Id)
	}

	page2, err := svc.ListTenants(ctx, &adminv1.ListTenantsRequest{PageSize: 2, PageToken: page1.NextPageToken})
	requireOK(t, err, "ListTenants page2")
	if len(page2.Tenants) != 1 || page2.Tenants[0].Id != "c" || page2.NextPageToken != "" {
		t.Errorf("page2 = %+v, want [c] with no further token", page2.Tenants)
	}

	_, err = svc.ListTenants(ctx, &adminv1.ListTenantsRequest{PageToken: "!!!not-valid-base64!!!"})
	requireCode(t, err, codes.InvalidArgument)
}

// TestTenantAdminService_ListDomainsPagination is the same regression
// coverage as ListTenantsPagination, for ListDomains — a proto with no
// order_by/filter fields, so the fixed hostname-ascending sort is what makes
// the two-page round trip deterministic.
func TestTenantAdminService_ListDomainsPagination(t *testing.T) {
	t.Parallel()
	store := tenantmemory.New()
	svc, _ := newTenantAdminServiceForTest(store, nil)
	ctx := context.Background()
	_, err := svc.CreateTenant(ctx, &adminv1.CreateTenantRequest{Tenant: &adminv1.Tenant{Id: "t1", Slug: "t1"}})
	requireOK(t, err, "CreateTenant")
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com"} {
		_, err := svc.CreateDomain(ctx, &adminv1.CreateDomainRequest{Domain: &adminv1.Domain{Hostname: host, TenantId: "t1"}})
		requireOK(t, err, "CreateDomain "+host)
	}

	page1, err := svc.ListDomains(ctx, &adminv1.ListDomainsRequest{PageSize: 2})
	requireOK(t, err, "ListDomains page1")
	if len(page1.Domains) != 2 || page1.TotalSize != 3 || page1.NextPageToken == "" {
		t.Fatalf("page1 = len=%d total=%d next=%q", len(page1.Domains), page1.TotalSize, page1.NextPageToken)
	}
	if page1.Domains[0].Hostname != "a.example.com" || page1.Domains[1].Hostname != "b.example.com" {
		t.Errorf("page1 hostnames = [%s, %s]", page1.Domains[0].Hostname, page1.Domains[1].Hostname)
	}

	page2, err := svc.ListDomains(ctx, &adminv1.ListDomainsRequest{PageSize: 2, PageToken: page1.NextPageToken})
	requireOK(t, err, "ListDomains page2")
	if len(page2.Domains) != 1 || page2.Domains[0].Hostname != "c.example.com" || page2.NextPageToken != "" {
		t.Errorf("page2 = %+v, want [c.example.com] with no further token", page2.Domains)
	}

	_, err = svc.ListDomains(ctx, &adminv1.ListDomainsRequest{PageToken: "!!!not-valid-base64!!!"})
	requireCode(t, err, codes.InvalidArgument)
}
