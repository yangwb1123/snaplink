package ssotest

import (
	"testing"

	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
)

func TestAdminGRPC_TenantCRUD(t *testing.T) {
	h := buildAdminGRPC(t)
	svc := adminv1.NewTenantAdminServiceClient(h.Conn)

	created, err := svc.CreateTenant(h.ctx, &adminv1.CreateTenantRequest{
		Tenant: validTenantProto("tenant-1", "tenant-1", "Tenant 1"),
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if created.GetTenant().GetId() != "tenant-1" {
		t.Fatalf("got id %q", created.GetTenant().GetId())
	}

	got, err := svc.GetTenant(h.ctx, &adminv1.GetTenantRequest{Id: "tenant-1"})
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.GetTenant().GetName() != "Tenant 1" {
		t.Fatalf("got name %q", got.GetTenant().GetName())
	}

	list, err := svc.ListTenants(h.ctx, &adminv1.ListTenantsRequest{})
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(list.GetTenants()) < 1 {
		t.Fatal("expected at least 1 tenant")
	}

	_, err = svc.GetTenant(h.ctx, &adminv1.GetTenantRequest{Id: "no-such-tenant"})
	if err == nil {
		t.Fatal("expected error for unknown tenant")
	}

	_, err = svc.DeleteTenant(h.ctx, &adminv1.DeleteTenantRequest{Id: "tenant-1"})
	if err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
}
