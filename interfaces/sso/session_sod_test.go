package sso_test

import (
	"context"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestDestroySessionDeactivatesPermissionRoles(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	if err := p.AddRole(ctx, "web", permissions.Role{Code: "approver", Permissions: []string{"request:approve"}}); err != nil {
		t.Fatalf("add role: %v", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"approver"}); err != nil {
		t.Fatalf("assign role: %v", err)
	}
	sessions := defaultimpl.NewMemorySessionManager()
	session, err := sessions.CreateWithMeta(ctx, "alice", core.SessionMeta{ClientID: "web"})
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	if err := p.ActivateRoles(ctx, "alice", "web", session.ID, []string{"approver"}); err != nil {
		t.Fatalf("activate role: %v", err)
	}
	srv := sso.NewServer(
		sso.WithSessionManager(sessions),
		sso.WithPermissionProvider(p),
	)
	if err := srv.DestroySession(ctx, session.ID); err != nil {
		t.Fatalf("destroy session: %v", err)
	}
	roles, err := p.ActiveRoles(ctx, "alice", "web", session.ID)
	if err != nil {
		t.Fatalf("list active roles: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("active roles after logout = %+v", roles)
	}
}
