package sqlite

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
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

func TestProvider_SoD_ConcurrentRoleAddsSerialize(t *testing.T) {
	dsn := "file:" + filepath.Join(t.TempDir(), "permissions.db") + "?_journal=WAL"
	p1, err := New(dsn)
	if err != nil {
		t.Fatalf("New p1: %v", err)
	}
	t.Cleanup(func() { _ = p1.Close() })
	p2, err := New(dsn)
	if err != nil {
		t.Fatalf("New p2: %v", err)
	}
	t.Cleanup(func() { _ = p2.Close() })
	ctx := context.Background()
	for _, code := range []string{"reader", "writer"} {
		if err := p1.AddRole(ctx, "web", permissions.Role{Code: code}); err != nil {
			t.Fatalf("AddRole %s: %v", code, err)
		}
	}
	start := make(chan struct{})
	errs := make(chan error, 2)
	var wg sync.WaitGroup
	for i, provider := range []*Provider{p1, p2} {
		role := []string{"reader", "writer"}[i]
		wg.Add(1)
		go func(p *Provider, code string) {
			defer wg.Done()
			<-start
			errs <- p.AddRoleToUser(ctx, "alice", "web", code)
		}(provider, role)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent AddRoleToUser: %v", err)
		}
	}
	roles, err := p1.Roles(ctx, "alice", "web")
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	got := make(map[string]bool, len(roles))
	for _, role := range roles {
		got[role.Code] = true
	}
	if !got["reader"] || !got["writer"] || len(got) != 2 {
		t.Fatalf("concurrent roles = %v, want reader+writer", got)
	}
}
