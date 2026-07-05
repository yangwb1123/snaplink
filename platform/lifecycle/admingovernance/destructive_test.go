package admingovernance

import "testing"

func TestDestructiveSet_Match(t *testing.T) {
	set := NewDestructiveSet([]DestructiveRule{
		{Method: "DELETE", PathPrefix: "/api/v1/admin/tenants/", Action: "tenant_delete"},
		{Method: "DELETE", PathPrefix: "/api/v1/admin/clients/", Action: "client_delete"},
	})

	action, ok := set.Match("DELETE", "/api/v1/admin/tenants/acme-corp")
	if !ok || action != "tenant_delete" {
		t.Fatalf("Match tenant delete = (%q, %v)", action, ok)
	}

	if _, ok := set.Match("GET", "/api/v1/admin/tenants/acme-corp"); ok {
		t.Error("GET must not match a DELETE-only rule")
	}
	if _, ok := set.Match("DELETE", "/api/v1/admin/connections/abc"); ok {
		t.Error("unrelated path must not match")
	}
}

func TestDestructiveSet_Empty(t *testing.T) {
	var set DestructiveSet
	if _, ok := set.Match("DELETE", "/api/v1/admin/tenants/acme"); ok {
		t.Error("empty set must classify nothing as destructive")
	}
}
