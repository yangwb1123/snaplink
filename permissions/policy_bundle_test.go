package permissions_test

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/snaplink/sso/permissions"
)

// bundleProvider seeds two roles (out of code order, and with permissions
// out of order) under one client so the test can assert BuildPolicyBundle
// canonicalizes both into a stable order.
func bundleProvider(t *testing.T) *permissions.MemoryProvider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	// Add "viewer" before "admin" and permissions unsorted so the test
	// proves BuildPolicyBundle sorts, not just preserves insertion order.
	if err := p.AddRole(context.Background(), "web-app", permissions.Role{
		Code:        "viewer",
		Name:        "Viewer",
		Description: "read-only",
		Permissions: []string{"order:read", "user:read"},
	}); err != nil {
		t.Fatalf("add viewer: %v", err)
	}
	if err := p.AddRole(context.Background(), "web-app", permissions.Role{
		Code:        "admin",
		Name:        "Administrator",
		Permissions: []string{"user:*", "audit:read", "order:*"},
	}); err != nil {
		t.Fatalf("add admin: %v", err)
	}
	return p
}

func TestBuildPolicyBundle_SerializesRolesAndSemantics(t *testing.T) {
	p := bundleProvider(t)
	b, err := permissions.BuildPolicyBundle(context.Background(), p, "web-app")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if b.Version != permissions.PolicyBundleVersion {
		t.Fatalf("version = %d, want %d", b.Version, permissions.PolicyBundleVersion)
	}
	if b.ClientID != "web-app" {
		t.Fatalf("client_id = %q", b.ClientID)
	}
	if len(b.Roles) != 2 {
		t.Fatalf("roles = %d, want 2", len(b.Roles))
	}
	// Roles sorted by Code: admin before viewer.
	if b.Roles[0].Code != "admin" || b.Roles[1].Code != "viewer" {
		t.Fatalf("roles not sorted by code: %q, %q", b.Roles[0].Code, b.Roles[1].Code)
	}
	// admin's permissions sorted: audit:read, order:*, user:*
	wantAdmin := []string{"audit:read", "order:*", "user:*"}
	if len(b.Roles[0].Permissions) != len(wantAdmin) {
		t.Fatalf("admin perms = %v", b.Roles[0].Permissions)
	}
	for i, w := range wantAdmin {
		if b.Roles[0].Permissions[i] != w {
			t.Fatalf("admin perm[%d] = %q, want %q", i, b.Roles[0].Permissions[i], w)
		}
	}
	if b.Roles[1].Name != "Viewer" || b.Roles[1].Description != "read-only" {
		t.Fatalf("viewer name/desc not carried: %+v", b.Roles[1])
	}

	// Static wildcard semantics match the matcher contract.
	sem := b.WildcardSemantics
	if sem.AllToken != permissions.WildcardAll || sem.DomainSuffix != permissions.WildcardSuffix || sem.Separator != ":" {
		t.Fatalf("semantics = %+v", sem)
	}
	if len(sem.Rules) == 0 {
		t.Fatalf("semantics rules empty")
	}

	// generated_at is stamped (informational).
	if b.GeneratedAt.IsZero() {
		t.Fatalf("generated_at not stamped")
	}

	// The bundle round-trips through JSON without loss of the role set.
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back permissions.PolicyBundle
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(back.Roles) != 2 || back.Roles[0].Code != "admin" {
		t.Fatalf("round-trip lost roles: %+v", back.Roles)
	}
}

// TestBuildPolicyBundle_CanonicalBytesStableAcrossRebuilds is the ETag
// stability guarantee: rebuilding the bundle from the SAME role set (even
// at a later time, even when the provider's map iteration order differs)
// must yield byte-identical CanonicalBytes, since the ETag is hashed over
// those bytes and a sidecar's If-None-Match relies on it.
func TestBuildPolicyBundle_CanonicalBytesStableAcrossRebuilds(t *testing.T) {
	p := bundleProvider(t)
	b1, err := permissions.BuildPolicyBundle(context.Background(), p, "web-app")
	if err != nil {
		t.Fatalf("build 1: %v", err)
	}
	b2, err := permissions.BuildPolicyBundle(context.Background(), p, "web-app")
	if err != nil {
		t.Fatalf("build 2: %v", err)
	}
	c1, c2 := b1.CanonicalBytes(), b2.CanonicalBytes()
	if !bytes.Equal(c1, c2) {
		t.Fatalf("canonical bytes not stable across rebuilds:\n%x\n%x", c1, c2)
	}
	// generated_at differs (or may), but it MUST NOT appear in the
	// canonical bytes — force a divergent timestamp and re-check.
	b2.GeneratedAt = b1.GeneratedAt.Add(1000)
	if !bytes.Equal(c1, b2.CanonicalBytes()) {
		t.Fatalf("generated_at leaked into canonical bytes")
	}
}

// TestBuildPolicyBundle_CanonicalBytesChangeOnRoleEdit proves the ETag
// actually tracks content: editing a role's permissions changes the
// canonical bytes (and thus the ETag), so a sidecar re-fetches.
func TestBuildPolicyBundle_CanonicalBytesChangeOnRoleEdit(t *testing.T) {
	p := bundleProvider(t)
	before, _ := permissions.BuildPolicyBundle(context.Background(), p, "web-app")
	if err := p.UpdateRole(context.Background(), "web-app", permissions.Role{
		Code:        "viewer",
		Name:        "Viewer",
		Description: "read-only",
		Permissions: []string{"order:read", "user:read", "report:read"},
	}); err != nil {
		t.Fatalf("update: %v", err)
	}
	after, _ := permissions.BuildPolicyBundle(context.Background(), p, "web-app")
	if bytes.Equal(before.CanonicalBytes(), after.CanonicalBytes()) {
		t.Fatalf("canonical bytes unchanged after a role edit")
	}
}

// TestBuildPolicyBundle_UnknownClientEmpty: an unknown client yields an
// empty role set, not an error (the bundle is still well-formed).
func TestBuildPolicyBundle_UnknownClientEmpty(t *testing.T) {
	p := permissions.NewMemoryProvider()
	b, err := permissions.BuildPolicyBundle(context.Background(), p, "nope")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(b.Roles) != 0 {
		t.Fatalf("expected empty roles, got %d", len(b.Roles))
	}
}
