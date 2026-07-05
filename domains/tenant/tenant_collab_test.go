package tenant

import "testing"

func TestGuestRecord_Validate(t *testing.T) {
	cases := []struct {
		name    string
		g       GuestRecord
		wantErr bool
	}{
		{"valid", GuestRecord{GuestTenantID: "guest", HomeTenantID: "home", ExternalSubjectID: "u1"}, false},
		{"missing guest tenant", GuestRecord{HomeTenantID: "home", ExternalSubjectID: "u1"}, true},
		{"missing home tenant", GuestRecord{GuestTenantID: "guest", ExternalSubjectID: "u1"}, true},
		{"missing subject", GuestRecord{GuestTenantID: "guest", HomeTenantID: "home"}, true},
		{"same tenant", GuestRecord{GuestTenantID: "acme", HomeTenantID: "acme", ExternalSubjectID: "u1"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.g.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}

func TestTenantCollaboration_Validate(t *testing.T) {
	cases := []struct {
		name    string
		c       TenantCollaboration
		wantErr bool
	}{
		{"valid", TenantCollaboration{GuestTenantID: "guest", HomeTenantID: "home"}, false},
		{"missing guest tenant", TenantCollaboration{HomeTenantID: "home"}, true},
		{"missing home tenant", TenantCollaboration{GuestTenantID: "guest"}, true},
		{"same tenant", TenantCollaboration{GuestTenantID: "acme", HomeTenantID: "acme"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.c.Validate()
			if (err != nil) != tc.wantErr {
				t.Errorf("Validate() err=%v, wantErr=%v", err, tc.wantErr)
			}
		})
	}
}
