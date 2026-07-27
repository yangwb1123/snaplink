package scim

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestRoleToGroup(t *testing.T) {
	role := permissions.Role{
		Code:        "admin",
		Name:        "Administrator",
		Permissions: []string{"user:read", "user:write"},
	}
	members := []string{"user-1", "user-2"}
	location := "https://scim.example.com/Groups/admin"

	group := RoleToGroup(role, members, location)

	if group.ID != "admin" {
		t.Errorf("expected ID 'admin', got %q", group.ID)
	}
	if group.DisplayName != "Administrator" {
		t.Errorf("expected DisplayName 'Administrator', got %q", group.DisplayName)
	}
	if len(group.Members) != 2 {
		t.Errorf("expected 2 members, got %d", len(group.Members))
	}
	if group.Members[0].Value != "user-1" {
		t.Errorf("expected first member 'user-1', got %q", group.Members[0].Value)
	}
	if group.Meta.Location != location {
		t.Errorf("expected location %q, got %q", location, group.Meta.Location)
	}
	if len(group.Schemas) != 1 || group.Schemas[0] != SchemaGroup {
		t.Errorf("expected SchemaGroup schema")
	}
}

func TestRoleToGroup_NoMembers(t *testing.T) {
	role := permissions.Role{Code: "viewer", Name: "Viewer"}
	group := RoleToGroup(role, nil, "")

	if len(group.Members) != 0 {
		t.Errorf("expected 0 members, got %d", len(group.Members))
	}
}

func TestUserToResource(t *testing.T) {
	u := &core.User{
		ID:         "user-1",
		ExternalID: "ext-1",
		Name:       "Alice",
		Attributes: map[string]string{
			"email":  "alice@example.com",
			"status": "active",
		},
	}

	res := UserToResource(u, "https://scim.example.com/Users/user-1")

	if res.ID != "user-1" {
		t.Errorf("expected ID 'user-1', got %q", res.ID)
	}
	if res.ExternalID != "ext-1" {
		t.Errorf("expected ExternalID 'ext-1', got %q", res.ExternalID)
	}
	if res.DisplayName != "Alice" {
		t.Errorf("expected DisplayName 'Alice', got %q", res.DisplayName)
	}
	if res.Meta.Location != "https://scim.example.com/Users/user-1" {
		t.Errorf("unexpected location: %q", res.Meta.Location)
	}
}

func TestUserToResource_Minimal(t *testing.T) {
	u := &core.User{ID: "minimal-user"}
	res := UserToResource(u, "")

	if res.ID != "minimal-user" {
		t.Errorf("expected 'minimal-user', got %q", res.ID)
	}
	if res.ExternalID != "" {
		t.Errorf("expected empty ExternalID, got %q", res.ExternalID)
	}
	if res.UserName != "" {
		t.Errorf("expected empty UserName, got %q", res.UserName)
	}
}

func TestRoleMembers(t *testing.T) {
	// This requires a permission provider - test with memory provider
	permProvider := permissions.NewMemoryProvider()
	ctx := context.Background()

	err := permProvider.AddRole(ctx, "test-client", permissions.Role{
		Code: "test-role",
		Name: "Test Role",
	})
	if err != nil {
		t.Fatalf("CreateRole: %v", err)
	}

	members, err := RoleMembers(ctx, permProvider, "test-client", "test-role")
	if err != nil {
		t.Fatalf("RoleMembers: %v", err)
	}
	// No members assigned yet
	if len(members) != 0 {
		t.Errorf("expected 0 members, got %d", len(members))
	}
}
