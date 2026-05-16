package tenant_test

import (
	"errors"
	"testing"

	"github.com/snaplink/sso/tenant"
)

func TestTenantValidate_Happy(t *testing.T) {
	tt := &tenant.Tenant{ID: "t1", Slug: "acme", Name: "Acme"}
	if err := tt.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if tt.Status != tenant.StatusActive {
		t.Errorf("default status = %q, want active", tt.Status)
	}
}

func TestTenantValidate_RejectsMissingID(t *testing.T) {
	tt := &tenant.Tenant{Slug: "acme"}
	if err := tt.Validate(); !errors.Is(err, tenant.ErrInvalidTenant) {
		t.Errorf("err = %v, want ErrInvalidTenant", err)
	}
}

func TestTenantValidate_RejectsMissingSlug(t *testing.T) {
	tt := &tenant.Tenant{ID: "t1"}
	if err := tt.Validate(); !errors.Is(err, tenant.ErrInvalidTenant) {
		t.Errorf("err = %v, want ErrInvalidTenant", err)
	}
}

func TestTenantValidate_PreservesExplicitStatus(t *testing.T) {
	tt := &tenant.Tenant{ID: "t1", Slug: "acme", Status: tenant.StatusSuspended}
	_ = tt.Validate()
	if tt.Status != tenant.StatusSuspended {
		t.Errorf("status overwritten: %q", tt.Status)
	}
}

func TestDomainValidate_Happy(t *testing.T) {
	d := &tenant.Domain{Hostname: "acme.com", TenantID: "t1"}
	if err := d.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
}

func TestDomainValidate_RejectsMissingHostname(t *testing.T) {
	d := &tenant.Domain{TenantID: "t1"}
	if err := d.Validate(); !errors.Is(err, tenant.ErrInvalidDomain) {
		t.Errorf("err = %v", err)
	}
}

func TestDomainValidate_RejectsMissingTenant(t *testing.T) {
	d := &tenant.Domain{Hostname: "acme.com"}
	if err := d.Validate(); !errors.Is(err, tenant.ErrInvalidDomain) {
		t.Errorf("err = %v", err)
	}
}
