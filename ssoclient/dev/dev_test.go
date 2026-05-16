package dev_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ssoclient"
	"github.com/snaplink/sso/ssoclient/dev"
)

func TestAuthClient_DefaultSubject(t *testing.T) {
	c := dev.NewAuthClient(dev.WithSilent())
	s, err := c.ValidateToken(context.Background(), "anything-here")
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if s.ID != "dev-user" {
		t.Errorf("ID = %q want dev-user", s.ID)
	}
	if s.Attrs["email"] != "dev@local" {
		t.Errorf("email attr = %q", s.Attrs["email"])
	}
}

func TestAuthClient_WithUserID(t *testing.T) {
	c := dev.NewAuthClient(dev.WithSilent(), dev.WithUserID("alice"))
	s, _ := c.ValidateToken(context.Background(), "")
	if s.ID != "alice" {
		t.Errorf("ID = %q", s.ID)
	}
}

func TestAuthClient_WithSubject(t *testing.T) {
	custom := &ssoclient.Subject{ID: "bob", Audience: []string{"app-x"}, Scopes: []string{"admin"}}
	c := dev.NewAuthClient(dev.WithSilent(), dev.WithSubject(custom))
	s, _ := c.ValidateToken(context.Background(), "")
	if s.ID != "bob" || len(s.Audience) != 1 || s.Audience[0] != "app-x" {
		t.Errorf("WithSubject not applied: %+v", s)
	}
}

func TestAuthClient_WithAttr(t *testing.T) {
	c := dev.NewAuthClient(dev.WithSilent(), dev.WithAttr("tier", "gold"))
	s, _ := c.ValidateToken(context.Background(), "")
	if s.Attrs["tier"] != "gold" {
		t.Errorf("attr not set: %v", s.Attrs)
	}
}

func TestAuthClient_Logout_Always_OK(t *testing.T) {
	c := dev.NewAuthClient(dev.WithSilent())
	if err := c.Logout(context.Background(), &ssoclient.LogoutRequest{}); err != nil {
		t.Errorf("Logout: %v", err)
	}
	if err := c.Logout(context.Background(), nil); err != nil {
		t.Errorf("Logout(nil): %v", err)
	}
}

func TestAuthClient_AttrsAreDefensivelyCopied(t *testing.T) {
	// Mutating the returned Subject's Attrs must not affect the
	// next ValidateToken caller. Regression guard.
	c := dev.NewAuthClient(dev.WithSilent())
	s1, _ := c.ValidateToken(context.Background(), "")
	s1.Attrs["email"] = "tampered"
	s2, _ := c.ValidateToken(context.Background(), "")
	if s2.Attrs["email"] == "tampered" {
		t.Errorf("Attrs leaked across ValidateToken calls: %v", s2.Attrs)
	}
}

func TestAuthzClient_AllowAllByDefault(t *testing.T) {
	c := dev.NewAuthzClient(dev.WithSilentAuthz())
	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "anything"})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !ok {
		t.Errorf("AllowAll default should allow")
	}
}

func TestAuthzClient_WithPermissions(t *testing.T) {
	c := dev.NewAuthzClient(
		dev.WithSilentAuthz(),
		dev.WithPermissions("billing:read", "billing:write"),
	)
	// Granted
	if ok, _ := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "billing:read"}); !ok {
		t.Errorf("billing:read should be allowed")
	}
	// Denied
	if ok, _ := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "admin:read"}); ok {
		t.Errorf("admin:read should be denied")
	}
}

func TestAuthzClient_WildcardPermission(t *testing.T) {
	c := dev.NewAuthzClient(
		dev.WithSilentAuthz(),
		dev.WithPermissions("billing:*"),
	)
	if ok, _ := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "billing:read"}); !ok {
		t.Errorf("billing:* should match billing:read")
	}
	if ok, _ := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "admin:read"}); ok {
		t.Errorf("billing:* should NOT match admin:read")
	}
}

func TestAuthzClient_ListPermissions(t *testing.T) {
	c := dev.NewAuthzClient(
		dev.WithSilentAuthz(),
		dev.WithPermissions("a:b", "c:d"),
	)
	got, _ := c.ListPermissions(context.Background(), "", "")
	if len(got) != 2 {
		t.Errorf("got %d permissions, want 2", len(got))
	}
}

func TestAuthzClient_ListRoles(t *testing.T) {
	c := dev.NewAuthzClient(
		dev.WithSilentAuthz(),
		dev.WithRoles("admin", "viewer"),
	)
	got, _ := c.ListRoles(context.Background(), "", "")
	if len(got) != 2 || got[0].Code != "admin" {
		t.Errorf("roles wrong: %+v", got)
	}
}

func TestAuthzClient_GetMenus(t *testing.T) {
	tree := ssoclient.MenuTree{
		{ID: "1", Name: "Home"},
		{ID: "2", Name: "Settings"},
	}
	c := dev.NewAuthzClient(dev.WithSilentAuthz(), dev.WithMenus(tree))
	got, _ := c.GetMenus(context.Background(), "", "")
	if len(got) != 2 {
		t.Errorf("menus = %+v", got)
	}
}

func TestAuthzClient_CheckNilRequest_AllowAll(t *testing.T) {
	c := dev.NewAuthzClient(dev.WithSilentAuthz())
	if ok, _ := c.Check(context.Background(), nil); !ok {
		t.Errorf("AllowAll should tolerate nil request")
	}
}

func TestAuthzClient_CheckNilRequest_NoAllowAll(t *testing.T) {
	c := dev.NewAuthzClient(dev.WithSilentAuthz(), dev.WithAllowAll(false))
	if ok, _ := c.Check(context.Background(), nil); ok {
		t.Errorf("non-allow-all + nil request should deny")
	}
}

func TestAuditClient_RecordIsNoopByDefault(t *testing.T) {
	c := dev.NewAuditClient(dev.WithSilentAudit())
	if err := c.Record(context.Background(), &ssoclient.Event{}); err != nil {
		t.Errorf("Record: %v", err)
	}
}

func TestAuditClient_WithSink(t *testing.T) {
	var buf bytes.Buffer
	c := dev.NewAuditClient(dev.WithSilentAudit(), dev.WithSink(&buf))
	_ = c.Record(context.Background(), &ssoclient.Event{ActorID: "alice"})
	if !bytes.Contains(buf.Bytes(), []byte("alice")) {
		t.Errorf("sink missing actor: %q", buf.String())
	}
}

func TestAuditClient_NilEvent_NoWrite(t *testing.T) {
	var buf bytes.Buffer
	c := dev.NewAuditClient(dev.WithSilentAudit(), dev.WithSink(&buf))
	_ = c.Record(context.Background(), nil)
	if buf.Len() != 0 {
		t.Errorf("nil event should not write: %q", buf.String())
	}
}

func TestAuditClient_Close_Always_OK(t *testing.T) {
	c := dev.NewAuditClient(dev.WithSilentAudit())
	if err := c.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// Interface assertions are compile-time in the package files; this is a
// belt-and-suspenders smoke test that the constructors return concrete
// values satisfying the public ssoclient interfaces.
func TestClients_SatisfyInterfaces(t *testing.T) {
	var (
		_ ssoclient.AuthClient  = dev.NewAuthClient(dev.WithSilent())
		_ ssoclient.AuthzClient = dev.NewAuthzClient(dev.WithSilentAuthz())
		_ ssoclient.AuditClient = dev.NewAuditClient(dev.WithSilentAudit())
	)
}

// Sanity check that permissions.Matches works with the imported type
// (catches a future refactor breaking the alias chain).
func TestPermissionsMatchesAliased(t *testing.T) {
	p := []ssoclient.Permission{{Code: "x:*"}}
	if !permissions.Matches(p, "x:y") {
		t.Errorf("Matches across alias broken")
	}
}
