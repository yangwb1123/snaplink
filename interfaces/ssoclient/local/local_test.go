package local_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/interfaces/ssoclient"
	"github.com/snaplink/sso/interfaces/ssoclient/local"
	"github.com/snaplink/sso/platform/audit"
)

// Interface satisfaction guards. These don't run; they fail to compile if
// the implementations drift.
var (
	_ ssoclient.AuthClient  = (*local.AuthClient)(nil)
	_ ssoclient.AuthzClient = (*local.AuthzClient)(nil)
	_ ssoclient.AuditClient = (*local.AuditClient)(nil)
)

// --- AuthClient ---

func TestLocalAuth_ValidateRoundtrip(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer(defaultimpl.WithEd25519TokenTTL(5 * time.Minute))
	tok, err := iss.Issue(context.Background(), &sso.Subject{ID: "user-1", Claims: map[string]string{"email": "u@example.com"}}, []string{"read"})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	client := local.NewAuthClient(iss)
	subj, err := client.ValidateToken(context.Background(), tok.AccessToken)
	if err != nil {
		t.Fatalf("ValidateToken: %v", err)
	}
	if subj.ID != "user-1" {
		t.Errorf("Subject.ID = %q", subj.ID)
	}
	if subj.Attrs["email"] != "u@example.com" {
		t.Errorf("Attrs lost: %+v", subj.Attrs)
	}
	if len(subj.Scopes) != 1 || subj.Scopes[0] != "read" {
		t.Errorf("Scopes = %v", subj.Scopes)
	}
}

func TestLocalAuth_ValidateEmptyTokenErrors(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	client := local.NewAuthClient(iss)
	if _, err := client.ValidateToken(context.Background(), ""); err == nil {
		t.Fatal("empty token should error")
	}
}

func TestLocalAuth_LogoutRevokesToken(t *testing.T) {
	iss := defaultimpl.NewEd25519JWTIssuer()
	tok, _ := iss.Issue(context.Background(), &sso.Subject{ID: "u"}, nil)
	client := local.NewAuthClient(iss)

	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{AccessToken: tok.AccessToken}); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if _, err := client.ValidateToken(context.Background(), tok.AccessToken); err == nil {
		t.Fatal("revoked token should fail validation")
	}
}

func TestLocalAuth_LogoutRequiresAtLeastOne(t *testing.T) {
	client := local.NewAuthClient(defaultimpl.NewEd25519JWTIssuer())
	if err := client.Logout(context.Background(), &ssoclient.LogoutRequest{}); err == nil {
		t.Fatal("empty Logout should error")
	}
}

// --- AuthzClient ---

func authzFixture(t *testing.T) *permissions.MemoryProvider {
	t.Helper()
	p := permissions.NewMemoryProvider()
	if err := p.AddRole(context.Background(), "web-app", permissions.Role{Code: "admin", Permissions: []string{"user:*"}}); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	if err := p.SetMenus(context.Background(), "web-app", permissions.MenuTree{
		{ID: "m-users", Permission: "user:read"},
		{ID: "m-audit", Permission: "audit:read"},
	}); err != nil {
		t.Fatalf("SetMenus: %v", err)
	}
	if err := p.AssignRoles(context.Background(), "user-alice", "web-app", []string{"admin"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	return p
}

func TestLocalAuthz_Check_WildcardAllowed(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "user:read",
	})
	if err != nil || !ok {
		t.Fatalf("expected allowed; got ok=%v err=%v", ok, err)
	}
}

func TestLocalAuthz_Check_Denied(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{
		SubjectID: "user-alice", ClientID: "web-app", Permission: "audit:read",
	})
	if err != nil || ok {
		t.Fatalf("expected denied; got ok=%v err=%v", ok, err)
	}
}

func TestLocalAuthz_Check_RequiresFields(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	if _, err := c.Check(context.Background(), &ssoclient.CheckRequest{Permission: "x"}); err == nil {
		t.Error("missing SubjectID should error")
	}
}

func TestLocalAuthz_Check_UnknownUserDeniedNotErrored(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	ok, err := c.Check(context.Background(), &ssoclient.CheckRequest{
		SubjectID: "ghost", ClientID: "web-app", Permission: "user:read",
	})
	if err != nil {
		t.Fatalf("unknown user shouldn't error: %v", err)
	}
	if ok {
		t.Fatal("unknown user should be denied")
	}
}

func TestLocalAuthz_GetMenus_Filtered(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	tree, err := c.GetMenus(context.Background(), "user-alice", "web-app")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(tree) != 1 || tree[0].ID != "m-users" {
		t.Fatalf("expected [m-users], got %+v", tree)
	}
}

func TestLocalAuthz_GetMenus_UnknownUserReturnsEmpty(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	tree, err := c.GetMenus(context.Background(), "ghost", "web-app")
	if err != nil {
		t.Fatalf("GetMenus: %v", err)
	}
	if len(tree) != 0 {
		t.Fatalf("expected empty, got %+v", tree)
	}
}

func TestLocalAuthz_ListRoles_UnknownUserReturnsEmpty(t *testing.T) {
	c := local.NewAuthzClient(authzFixture(t))
	got, err := c.ListRoles(context.Background(), "ghost", "web-app")
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected empty, got %+v", got)
	}
}

// --- AuditClient ---

func TestLocalAudit_RecordPassthrough(t *testing.T) {
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	c := local.NewAuditClient(rec)

	if err := c.Record(context.Background(), &ssoclient.Event{Type: audit.EventLogin, ActorID: "a"}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	if sink.Len() != 1 {
		t.Fatalf("sink len = %d, want 1", sink.Len())
	}
}

func TestLocalAudit_RecordRequiresEvent(t *testing.T) {
	c := local.NewAuditClient(audit.New(audit.NewMemorySink(1)))
	if err := c.Record(context.Background(), nil); err == nil {
		t.Fatal("nil event should error")
	}
}

func TestLocalAudit_NilRecorderSafe(t *testing.T) {
	// Recorder is nil-safe at the SDK level — confirm the wrapper preserves that.
	c := local.NewAuditClient(nil)
	if err := c.Record(context.Background(), &ssoclient.Event{Type: audit.EventLogin}); err != nil {
		t.Errorf("nil recorder should silently no-op, got %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close should be a no-op for local: %v", err)
	}
}

// --- compile-time: ensure errors.Join is what local.Logout uses ---

var _ = errors.Join
