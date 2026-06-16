package permissions_test

import (
	"context"
	"errors"
	"testing"

	"github.com/snaplink/sso/permissions"
)

// listFailProvider embeds a real MemoryProvider but overrides ListAllRoles
// to surface a backend error, so BuildPolicyBundle's error-propagation
// branch runs without a mock framework.
type listFailProvider struct {
	*permissions.MemoryProvider
	err error
}

func (l listFailProvider) ListAllRoles(context.Context, string) ([]permissions.Role, error) {
	return nil, l.err
}

func TestBuildPolicyBundle_PropagatesListError(t *testing.T) {
	want := errors.New("store unavailable")
	prov := listFailProvider{MemoryProvider: permissions.NewMemoryProvider(), err: want}
	b, err := permissions.BuildPolicyBundle(context.Background(), prov, "web-app")
	if !errors.Is(err, want) {
		t.Fatalf("err=%v, want %v", err, want)
	}
	if b != nil {
		t.Fatalf("expected nil bundle on error, got %+v", b)
	}
}

// TestCanonicalBytes_EmptyBundleStable covers the zero-role / itoa(0) path:
// an empty bundle still produces deterministic, non-empty canonical bytes
// (it frames version + client + semantics + a "0" role count), and two
// empty bundles for the same client hash identically.
func TestCanonicalBytes_EmptyBundleStable(t *testing.T) {
	p := permissions.NewMemoryProvider()
	b1, err := permissions.BuildPolicyBundle(context.Background(), p, "nobody")
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if len(b1.Roles) != 0 {
		t.Fatalf("expected empty role set, got %d", len(b1.Roles))
	}
	c1 := b1.CanonicalBytes()
	if len(c1) == 0 {
		t.Fatalf("empty bundle should still produce framed canonical bytes")
	}

	b2, _ := permissions.BuildPolicyBundle(context.Background(), p, "nobody")
	if string(c1) != string(b2.CanonicalBytes()) {
		t.Fatalf("empty-bundle canonical bytes not stable")
	}
}

// TestCanonicalBytes_RoleWithZeroPermissions exercises itoa(0) via a role
// that grants no permissions (len(r.Permissions)==0 → writeField(itoa(0))),
// and confirms it stays distinct from a role that grants one.
func TestCanonicalBytes_RoleWithZeroPermissions(t *testing.T) {
	ctx := context.Background()
	pEmpty := permissions.NewMemoryProvider()
	_ = pEmpty.AddRole(ctx, "c", permissions.Role{Code: "r"}) // no permissions
	bEmpty, _ := permissions.BuildPolicyBundle(ctx, pEmpty, "c")
	if len(bEmpty.Roles) != 1 || len(bEmpty.Roles[0].Permissions) != 0 {
		t.Fatalf("expected one zero-permission role, got %+v", bEmpty.Roles)
	}

	pOne := permissions.NewMemoryProvider()
	_ = pOne.AddRole(ctx, "c", permissions.Role{Code: "r", Permissions: []string{"x:read"}})
	bOne, _ := permissions.BuildPolicyBundle(ctx, pOne, "c")

	if string(bEmpty.CanonicalBytes()) == string(bOne.CanonicalBytes()) {
		t.Fatalf("zero-permission role must hash differently from a one-permission role")
	}
}
