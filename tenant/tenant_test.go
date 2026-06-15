package tenant

import (
	"testing"
)

func TestTenantValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tenant  Tenant
		wantErr bool
	}{
		{name: "valid tenant", tenant: Tenant{ID: "tenant1", Slug: "acme-corp"}, wantErr: false},
		{name: "missing id", tenant: Tenant{Slug: "acme-corp"}, wantErr: true},
		{name: "missing slug", tenant: Tenant{ID: "tenant1"}, wantErr: true},
		{name: "empty tenant", tenant: Tenant{}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.tenant.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate() expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}

func TestDomainValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		domain  Domain
		wantErr bool
	}{
		{name: "valid domain", domain: Domain{Hostname: "example.com", TenantID: "t1"}, wantErr: false},
		{name: "missing domain", domain: Domain{TenantID: "t1"}, wantErr: true},
		{name: "missing tenant id", domain: Domain{Hostname: "example.com"}, wantErr: true},
		{name: "empty domain", domain: Domain{}, wantErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := tc.domain.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate() expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate() unexpected error: %v", err)
			}
		})
	}
}
