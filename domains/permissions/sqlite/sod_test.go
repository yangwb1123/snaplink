package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

func TestProvider_SoD_AssignmentAndActivationPersist(t *testing.T) {
	p, err := New("file:" + filepath.Join(t.TempDir(), "permissions.db") + "?_journal=WAL")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ctx := context.Background()
	for _, code := range []string{"approver", "requester"} {
		if err := p.AddRole(ctx, "web", permissions.Role{Code: code, Permissions: []string{code + ":use"}}); err != nil {
			t.Fatalf("AddRole: %v", err)
		}
	}
	if err := p.SetConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetConflictSets: %v", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"approver", "requester"}); !errors.Is(err, permissions.ErrRoleConflict) {
		t.Fatalf("conflicting AssignRoles = %v, want ErrRoleConflict", err)
	}
	if err := p.AssignRoles(ctx, "alice", "web", []string{"approver"}); err != nil {
		t.Fatalf("AssignRoles: %v", err)
	}
	if err := p.SetActivationConflictSets(ctx, "web", [][]string{{"approver", "requester"}}); err != nil {
		t.Fatalf("SetActivationConflictSets: %v", err)
	}
	if err := p.ActivateRoles(ctx, "alice", "web", "sid-1", []string{"approver"}); err != nil {
		t.Fatalf("ActivateRoles: %v", err)
	}
	active, err := p.ActiveRoles(ctx, "alice", "web", "sid-1")
	if err != nil || len(active) != 1 || active[0].Code != "approver" {
		t.Fatalf("ActiveRoles = %+v, %v", active, err)
	}
	if err := p.DeactivateSession(ctx, "alice", "web", "sid-1"); err != nil {
		t.Fatalf("DeactivateSession: %v", err)
	}
	active, err = p.ActiveRoles(ctx, "alice", "web", "sid-1")
	if err != nil || len(active) != 0 {
		t.Fatalf("ActiveRoles after deactivate = %+v, %v", active, err)
	}
}
